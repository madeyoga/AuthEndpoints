using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.External.Google;

/// <summary>
/// Maps Google external auth login and callback endpoints.
/// </summary>
public static class GoogleEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps <c>login/google</c> and <c>login/google/callback</c>.
    /// Requires <c>AddGoogle</c> on <see cref="ExternalAuthBuilder"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapGoogleAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        return endpoints.MapExternalAuthProvider<TUser>(GoogleDefaults.AuthenticationScheme);
    }
}
