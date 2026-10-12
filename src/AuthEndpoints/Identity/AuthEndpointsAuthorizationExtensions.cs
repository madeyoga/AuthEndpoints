using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;

namespace AuthEndpoints.Identity;

/// <summary>
/// Authorization conventions for AuthEndpoints sign-in schemes.
/// </summary>
public static class AuthEndpointsAuthorizationExtensions
{
    /// <summary>
    /// Requires a signed-in user on whichever of the application cookie, Identity bearer,
    /// and JWT bearer schemes are registered. A ReAuth cookie or token is not a sign-in.
    /// </summary>
    public static TBuilder RequireAuthEndpointsUser<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.Add(endpointBuilder =>
        {
            endpointBuilder.Metadata.Add(
                ManagementAuthorization.CreateAttribute(endpointBuilder.ApplicationServices));
        });
        return builder;
    }
}
