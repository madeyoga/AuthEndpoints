using AspNet.Security.OAuth.GitHub;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.External.GitHub;

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
                configure(options);
            });

        builder.AddProvider<GitHubExternalAuthProvider>();
        return builder;
    }
}
