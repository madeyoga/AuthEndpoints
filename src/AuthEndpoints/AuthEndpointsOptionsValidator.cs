using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

internal sealed class AuthEndpointsOptionsValidator : IValidateOptions<AuthEndpointsOptions>
{
    private readonly IHostEnvironment _environment;

    public AuthEndpointsOptionsValidator(IHostEnvironment environment)
    {
        _environment = environment;
    }

    public ValidateOptionsResult Validate(string? name, AuthEndpointsOptions options)
    {
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

        return ValidateOptionsResult.Success;
    }
}

/// <summary>
/// Production check for a real <see cref="IEmailSender{TUser}"/> (not the Identity no-op).
/// </summary>
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
        if (!_environment.IsProduction() || !options.RequireEmailSenderInProduction)
        {
            return ValidateOptionsResult.Success;
        }

        using var scope = _scopeFactory.CreateScope();
        var sender = scope.ServiceProvider.GetService<IEmailSender<TUser>>();
        if (sender is null || IsFrameworkEmailSender(sender))
        {
            return ValidateOptionsResult.Fail(
                "AuthEndpoints: A real IEmailSender<TUser> must be registered in Production " +
                "(the Identity no-op sender is not allowed). " +
                "Example: services.AddTransient<IEmailSender<AppUser>, MyEmailSender>(); " +
                "Or set RequireEmailSenderInProduction = false to opt out (not recommended).");
        }

        return ValidateOptionsResult.Success;
    }

    private static bool IsFrameworkEmailSender(IEmailSender<TUser> sender)
    {
        var assemblyName = sender.GetType().Assembly.GetName().Name ?? string.Empty;
        return assemblyName.StartsWith("Microsoft.AspNetCore.Identity", StringComparison.Ordinal)
            || assemblyName.StartsWith("Microsoft.Extensions.Identity", StringComparison.Ordinal)
            || sender.GetType().Name.Contains("NoOp", StringComparison.OrdinalIgnoreCase);
    }
}
