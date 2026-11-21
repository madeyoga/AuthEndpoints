using System.Security.Claims;
using System.Text.Json;
using AuthEndpoints.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Validation;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// Runs last when OpenIddict validation authenticates an access token. Marks the identity as a delegated caller
/// (<see cref="CallerKinds.ClaimType"/> = <see cref="CallerKinds.Delegated"/>) and records the acting client in the RFC 8693
/// <c>act</c> claim (<c>{"client_id":"…"}</c>), next to <c>sub</c>. Both are added on the validated principal only,
/// so they also cover tokens issued before this existed. A claim already present is kept.
/// </summary>
internal sealed class AttachDelegatedCallerClaims : IOpenIddictValidationHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>
{
    public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
        = OpenIddictValidationHandlerDescriptor.CreateBuilder<OpenIddictValidationEvents.ProcessAuthenticationContext>()
            .UseSingletonHandler<AttachDelegatedCallerClaims>()
            .SetOrder(int.MaxValue - 100_000)
            .SetType(OpenIddictValidationHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(OpenIddictValidationEvents.ProcessAuthenticationContext context)
    {
        if (context.IsRejected || context.AccessTokenPrincipal?.Identity is not ClaimsIdentity { IsAuthenticated: true } identity)
        {
            return ValueTask.CompletedTask;
        }

        if (!identity.HasClaim(claim => claim.Type == CallerKinds.ClaimType))
        {
            identity.AddClaim(new Claim(CallerKinds.ClaimType, CallerKinds.Delegated));
        }

        var clientId = context.AccessTokenPrincipal.GetPresenters().FirstOrDefault()
            ?? context.AccessTokenPrincipal.GetClaim(OpenIddictConstants.Claims.ClientId);
        if (!string.IsNullOrEmpty(clientId) && !identity.HasClaim(claim => claim.Type == CallerKinds.ActorClaimType))
        {
            identity.AddClaim(new Claim(
                CallerKinds.ActorClaimType,
                JsonSerializer.Serialize(new Dictionary<string, string> { ["client_id"] = clientId }),
                Microsoft.IdentityModel.JsonWebTokens.JsonClaimValueTypes.Json));
        }

        return ValueTask.CompletedTask;
    }
}
