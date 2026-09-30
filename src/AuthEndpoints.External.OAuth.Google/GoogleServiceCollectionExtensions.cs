using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
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
    /// <c>email_verified</c> is taken from the userinfo payload after the host <c>configure</c> delegate.
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
                configure(options);
                options.SignInScheme = IdentityConstants.ExternalScheme;
                options.SaveTokens = false;
                options.Events ??= new OAuthEvents();
                OAuthTicketChain.Seal(options.Events, context =>
                {
                    if (context.Identity is not null)
                    {
                        GoogleEmailProof.Apply(context.Identity, context.User);
                    }

                    return Task.CompletedTask;
                });
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
