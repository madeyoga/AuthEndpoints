using AspNet.Security.OAuth.GitHub;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.External.OAuth.GitHub;

/// <summary>
/// Maps GitHub external auth login and callback endpoints.
/// </summary>
public static class GitHubEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps <c>login/github</c> and <c>login/github/callback</c>.
    /// Requires <c>AddGitHub</c> on <see cref="ExternalAuthBuilder"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapGitHubAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        return endpoints.MapExternalAuthProvider<TUser>(GitHubAuthenticationDefaults.AuthenticationScheme);
    }
}
