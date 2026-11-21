using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;

namespace AuthEndpoints.Identity;

public static class AuthEndpointsAuthorizationExtensions
{
    /// <summary>
    /// Requires a signed-in person on whichever of the application cookie, Identity bearer,
    /// and JWT bearer schemes are registered. A ReAuth cookie or token is not a sign-in.
    /// The caller must be a person calling directly (<see cref="DirectPersonRequirement"/>): an identity
    /// whose <see cref="CallerKinds.ClaimType"/> says otherwise gets <c>403</c>.
    /// </summary>
    public static TBuilder RequireAuthEndpointsUser<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.Add(endpointBuilder =>
        {
            endpointBuilder.Metadata.Add(
                ManagementAuthorization.CreateAttribute(endpointBuilder.ApplicationServices));
            endpointBuilder.Metadata.Add(DirectPersonPolicy.Instance);
        });
        return builder;
    }
}
