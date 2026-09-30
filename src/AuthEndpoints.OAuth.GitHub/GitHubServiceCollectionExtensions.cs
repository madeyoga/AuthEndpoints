using AspNet.Security.OAuth.GitHub;
using AuthEndpoints.External.OAuth;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.OAuth.GitHub;

/// <summary>
/// GitHub OAuth registration for <see cref="ExternalAuthBuilder"/>.
/// </summary>
public static class GitHubServiceCollectionExtensions
{
    /// <summary>
    /// Adds GitHub as an external authentication provider.
    /// The library calls <c>GET /user/emails</c> after the host <c>configure</c> delegate and keeps a verified address only.
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
                configure(options);
                options.SignInScheme = IdentityConstants.ExternalScheme;
                options.SaveTokens = false;
                if (!options.Scope.Contains("user:email"))
                {
                    options.Scope.Add("user:email");
                }

                options.Events ??= new OAuthEvents();
                OAuthTicketChain.Seal(options.Events, context =>
                {
                    if (context.Identity is null)
                    {
                        return Task.CompletedTask;
                    }

                    return GitHubUserEmails.ApplyAsync(
                        context.Identity,
                        context.Backchannel,
                        context.AccessToken,
                        context.HttpContext.RequestAborted);
                });
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
