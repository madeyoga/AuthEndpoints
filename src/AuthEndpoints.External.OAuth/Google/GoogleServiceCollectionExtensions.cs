using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth.Google;

/// <summary>
/// Google OAuth registration for <see cref="ExternalAuthBuilder"/>.
/// </summary>
public static class GoogleServiceCollectionExtensions
{
    /// <summary>
    /// Adds Google as an external authentication provider.
    /// </summary>
    public static ExternalAuthBuilder AddGoogle(
        this ExternalAuthBuilder builder,
        Action<GoogleOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services
            .AddAuthentication()
            .AddGoogle(options =>
            {
                options.SignInScheme = IdentityConstants.ExternalScheme;
                configure(options);
            });

        builder.Services.AddSingleton<IValidateOptions<GoogleOptions>, GoogleOAuthOptionsValidator>();
        builder.Services.AddOptions<GoogleOptions>(GoogleDefaults.AuthenticationScheme)
            .ValidateOnStart();

        builder.AddProvider<GoogleExternalAuthProvider>();
        return builder;
    }
}

internal sealed class GoogleOAuthOptionsValidator : IValidateOptions<GoogleOptions>
{
    public ValidateOptionsResult Validate(string? name, GoogleOptions options)
    {
        if (!string.Equals(name, GoogleDefaults.AuthenticationScheme, StringComparison.Ordinal))
        {
            return ValidateOptionsResult.Success;
        }

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            return ValidateOptionsResult.Fail("Google OAuth ClientId is required.");
        }

        if (string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            return ValidateOptionsResult.Fail("Google OAuth ClientSecret is required.");
        }

        return ValidateOptionsResult.Success;
    }
}
