using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

internal sealed class AuthEndpointsOptionsValidator : IValidateOptions<AuthEndpointsOptions>
{
    private readonly IHostEnvironment _environment;
    private readonly IServiceProvider _services;

    public AuthEndpointsOptionsValidator(IHostEnvironment environment, IServiceProvider services)
    {
        _environment = environment;
        _services = services;
    }

    public ValidateOptionsResult Validate(string? name, AuthEndpointsOptions options)
    {
        if (_services.GetService<PasswordAuthRegistration>() is not null)
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: AddAuthEndpoints and AddPasswordAuth cannot be used in the same host. Use one facade.");
        }

        if (string.IsNullOrWhiteSpace(options.IdentityPath) || !options.IdentityPath.StartsWith('/'))
        {
            return ValidateOptionsResult.Fail("AuthEndpoints: IdentityPath must be a rooted path (e.g. \"/identity\").");
        }

        if (options.Passkeys.Enabled &&
            (string.IsNullOrWhiteSpace(options.PasskeyPath) || !options.PasskeyPath.StartsWith('/')))
        {
            return ValidateOptionsResult.Fail("AuthEndpoints: PasskeyPath must be a rooted path (e.g. \"/account\").");
        }

        if (_environment.IsProduction()
            && options.Passkeys.Enabled
            && string.IsNullOrWhiteSpace(options.Passkeys.ServerDomain))
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: Passkeys.ServerDomain must be set in Production when Passkeys.Enabled is true " +
                "(e.g. options.Passkeys.ServerDomain = \"example.com\").");
        }

        if (options.Jwt.Enabled
            && (string.IsNullOrWhiteSpace(options.Jwt.Path) || !options.Jwt.Path.StartsWith('/')))
        {
            return ValidateOptionsResult.Fail("AuthEndpoints: Jwt.Path must be a rooted path (e.g. \"/auth\").");
        }

        return EmailConfirmationValidation.Validate(
            _environment,
            options.EmailConfirmation.ConfirmEmailRedirectUri,
            options.EmailConfirmation.AllowedRedirectOrigins,
            "AuthEndpoints");
    }
}

internal static class EmailConfirmationValidation
{
    public static ValidateOptionsResult Validate(
        IHostEnvironment environment,
        string? confirmEmailRedirectUri,
        IList<string>? allowedRedirectOrigins,
        string owner)
    {
        if (ConfirmEmailRedirect.IsIllegal(confirmEmailRedirectUri))
        {
            return ValidateOptionsResult.Fail(
                $"{owner}: EmailConfirmation.ConfirmEmailRedirectUri must be a rooted path or an absolute http(s) URI.");
        }

        if (!ConfirmEmailRedirect.TryGetAbsolute(confirmEmailRedirectUri, out Uri absolute))
        {
            return ValidateOptionsResult.Success;
        }

        if (!environment.IsProduction())
        {
            return ValidateOptionsResult.Success;
        }

        if (string.Equals(absolute.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return ValidateOptionsResult.Fail(
                $"{owner}: EmailConfirmation.ConfirmEmailRedirectUri must use https in Production.");
        }

        IReadOnlyList<string> allowed = ConfirmEmailRedirect.AsReadOnlyOrigins(allowedRedirectOrigins ?? new List<string>());
        if (allowed.Count == 0)
        {
            return ValidateOptionsResult.Fail(
                $"{owner}: EmailConfirmation.AllowedRedirectOrigins must be set in Production when ConfirmEmailRedirectUri is an absolute URI.");
        }

        if (!ConfirmEmailRedirect.IsOriginAllowlisted(absolute, allowed))
        {
            return ValidateOptionsResult.Fail(
                $"{owner}: EmailConfirmation.ConfirmEmailRedirectUri origin must match an AllowedRedirectOrigins entry.");
        }

        return ValidateOptionsResult.Success;
    }
}

internal static class ProductionEmailSenderCheck
{
    public static ValidateOptionsResult Validate<TUser>(
        bool require,
        IHostEnvironment environment,
        IServiceScopeFactory scopeFactory,
        string owner)
        where TUser : class
    {
        if (!environment.IsProduction() || !require)
        {
            return ValidateOptionsResult.Success;
        }

        using var scope = scopeFactory.CreateScope();
        var sender = scope.ServiceProvider.GetService<IEmailSender<TUser>>();
        if (sender is null || IsFrameworkEmailSender(sender))
        {
            return ValidateOptionsResult.Fail(
                $"{owner}: A real IEmailSender<TUser> must be registered in Production " +
                "(the Identity no-op sender is not allowed). " +
                "Example: services.AddTransient<IEmailSender<AppUser>, MyEmailSender>(); " +
                "Or set RequireEmailSenderInProduction = false to opt out (not recommended).");
        }

        return ValidateOptionsResult.Success;
    }

    private static bool IsFrameworkEmailSender<TUser>(IEmailSender<TUser> sender)
        where TUser : class
    {
        var assemblyName = sender.GetType().Assembly.GetName().Name ?? string.Empty;
        return assemblyName.StartsWith("Microsoft.AspNetCore.Identity", StringComparison.Ordinal)
            || assemblyName.StartsWith("Microsoft.Extensions.Identity", StringComparison.Ordinal)
            || sender.GetType().Name.Contains("NoOp", StringComparison.OrdinalIgnoreCase);
    }
}

internal sealed class AuthEndpointsEmailSenderValidator<TUser> : IValidateOptions<AuthEndpointsOptions>
    where TUser : class
{
    private readonly IHostEnvironment _environment;
    private readonly IServiceScopeFactory _scopeFactory;

    public AuthEndpointsEmailSenderValidator(
        IHostEnvironment environment,
        IServiceScopeFactory scopeFactory)
    {
        _environment = environment;
        _scopeFactory = scopeFactory;
    }

    public ValidateOptionsResult Validate(string? name, AuthEndpointsOptions options)
    {
        return ProductionEmailSenderCheck.Validate<TUser>(
            options.RequireEmailSenderInProduction,
            _environment,
            _scopeFactory,
            "AuthEndpoints");
    }
}
