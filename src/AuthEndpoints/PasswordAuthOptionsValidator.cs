using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

internal sealed class PasswordAuthOptionsValidator : IValidateOptions<PasswordAuthOptions>
{
    private readonly IHostEnvironment _environment;
    private readonly IServiceProvider _services;

    public PasswordAuthOptionsValidator(IHostEnvironment environment, IServiceProvider services)
    {
        _environment = environment;
        _services = services;
    }

    public ValidateOptionsResult Validate(string? name, PasswordAuthOptions options)
    {
        if (_services.GetService<AuthEndpointsRegistration>() is not null)
        {
            return ValidateOptionsResult.Fail(
                "PasswordAuth: AddPasswordAuth and AddAuthEndpoints cannot be used in the same host. Use one facade.");
        }

        var registration = _services.GetService<PasswordAuthRegistration>();
        if (registration is not null)
        {
            var changed = new List<string>();
            if (options.Session != registration.Session)
            {
                changed.Add(nameof(PasswordAuthOptions.Session));
            }

            if (!string.Equals(options.Path, registration.Path, StringComparison.Ordinal))
            {
                changed.Add(nameof(PasswordAuthOptions.Path));
            }

            if (!string.Equals(options.Passkeys.ServerDomain, registration.ServerDomain, StringComparison.Ordinal))
            {
                changed.Add("Passkeys.ServerDomain");
            }

            if (changed.Count > 0)
            {
                return ValidateOptionsResult.Fail(
                    "PasswordAuth: Session, Path, and Passkeys.ServerDomain are fixed by AddPasswordAuth. " +
                    "A later Configure<PasswordAuthOptions> changed " + string.Join(", ", changed) + ". " +
                    "Set them in the AddPasswordAuth callback.");
            }
        }

        if (!Enum.IsDefined(options.Session))
        {
            return ValidateOptionsResult.Fail("PasswordAuth: Session must be Cookie or Jwt.");
        }

        if (options.Session == AuthEndpointsSession.IdentityBearer)
        {
            return ValidateOptionsResult.Fail(
                "PasswordAuth: Session IdentityBearer is not supported. Use Cookie or Jwt, or AddAuthEndpoints for Identity bearer.");
        }

        if (options.Session == AuthEndpointsSession.Jwt && options.Jwt is null)
        {
            return ValidateOptionsResult.Fail(
                "PasswordAuth: Session Jwt requires Jwt to be set (issuer, signing key, and optional RefreshTokenTransport).");
        }

        if (string.IsNullOrWhiteSpace(options.Path) || !options.Path.StartsWith('/'))
        {
            return ValidateOptionsResult.Fail("PasswordAuth: Path must be a rooted path (e.g. \"/auth\").");
        }

        if (_environment.IsProduction()
            && options.Passkeys.ServerDomain is not null
            && string.IsNullOrWhiteSpace(options.Passkeys.ServerDomain))
        {
            return ValidateOptionsResult.Fail(
                "PasswordAuth: Passkeys.ServerDomain must be a non-empty relying party domain in Production when it is set " +
                "(e.g. options.Passkeys.ServerDomain = \"example.com\"). Omit it to leave passkeys unmapped.");
        }

        return EmailConfirmationValidation.Validate(
            _environment,
            options.EmailConfirmation.ConfirmEmailRedirectUri,
            options.EmailConfirmation.AllowedRedirectOrigins,
            "PasswordAuth");
    }
}

internal sealed class PasswordAuthEmailSenderValidator<TUser> : IValidateOptions<PasswordAuthOptions>
    where TUser : class
{
    private readonly IHostEnvironment _environment;
    private readonly IServiceScopeFactory _scopeFactory;

    public PasswordAuthEmailSenderValidator(IHostEnvironment environment, IServiceScopeFactory scopeFactory)
    {
        _environment = environment;
        _scopeFactory = scopeFactory;
    }

    public ValidateOptionsResult Validate(string? name, PasswordAuthOptions options)
    {
        return ProductionEmailSenderCheck.Validate<TUser>(
            options.RequireEmailSenderInProduction,
            _environment,
            _scopeFactory,
            "PasswordAuth");
    }
}
