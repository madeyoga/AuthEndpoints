using System.Security.Claims;
using AspNet.Security.OAuth.GitHub;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth.GitHub;

/// <summary>
/// GitHub OAuth registration for <see cref="ExternalAuthBuilder"/>.
/// </summary>
public static class GitHubServiceCollectionExtensions
{
    /// <summary>
    /// Adds GitHub as an external authentication provider.
    /// </summary>
    public static ExternalAuthBuilder AddGitHub(
        this ExternalAuthBuilder builder,
        Action<GitHubAuthenticationOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services
            .AddAuthentication()
            .AddGitHub(options =>
            {
                options.SignInScheme = IdentityConstants.ExternalScheme;
                if (!options.Scope.Contains("user:email"))
                {
                    options.Scope.Add("user:email");
                }

                // AspNet.Security.OAuth.GitHub only surfaces a verified primary email when user:email is granted.
                // Mark it so RequireVerifiedEmail can succeed consistently with OIDC providers.
                var prior = options.Events.OnCreatingTicket;
                options.Events.OnCreatingTicket = async context =>
                {
                    if (prior is not null)
                    {
                        await prior(context);
                    }

                    if (context.Identity is null)
                    {
                        return;
                    }

                    var hasEmail = context.Identity.HasClaim(c =>
                        c.Type == ClaimTypes.Email || c.Type == "email");
                    var hasVerified = context.Identity.HasClaim(c =>
                        c.Type == ExternalEmailClaims.EmailVerifiedClaimType);

                    if (hasEmail && !hasVerified)
                    {
                        context.Identity.AddClaim(new Claim(ExternalEmailClaims.EmailVerifiedClaimType, "true"));
                    }
                };

                configure(options);
            });

        builder.Services.AddSingleton<IValidateOptions<GitHubAuthenticationOptions>, GitHubOAuthOptionsValidator>();
        builder.Services.AddOptions<GitHubAuthenticationOptions>(GitHubAuthenticationDefaults.AuthenticationScheme)
            .ValidateOnStart();

        builder.AddProvider<GitHubExternalAuthProvider>();
        return builder;
    }
}

internal sealed class GitHubOAuthOptionsValidator : IValidateOptions<GitHubAuthenticationOptions>
{
    public ValidateOptionsResult Validate(string? name, GitHubAuthenticationOptions options)
    {
        if (!string.Equals(name, GitHubAuthenticationDefaults.AuthenticationScheme, StringComparison.Ordinal))
        {
            return ValidateOptionsResult.Success;
        }

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            return ValidateOptionsResult.Fail("GitHub OAuth ClientId is required.");
        }

        if (string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            return ValidateOptionsResult.Fail("GitHub OAuth ClientSecret is required.");
        }

        return ValidateOptionsResult.Success;
    }
}
