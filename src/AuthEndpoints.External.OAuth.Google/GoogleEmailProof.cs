using System.Security.Claims;
using System.Text.Json;

namespace AuthEndpoints.External.OAuth.Google;

/// <summary>
/// Sets <c>email_verified</c> from the Google userinfo payload. A host ticket delegate cannot
/// leave a synthetic verified claim behind.
/// </summary>
internal static class GoogleEmailProof
{
    internal static bool? ReadVerified(JsonElement user)
    {
        if (user.ValueKind != JsonValueKind.Object
            || !user.TryGetProperty("email_verified", out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => bool.TryParse(value.GetString(), out var parsed) ? parsed : null,
            _ => null,
        };
    }

    internal static void Apply(ClaimsIdentity identity, JsonElement user)
    {
        ArgumentNullException.ThrowIfNull(identity);

        foreach (var claim in identity.FindAll(ExternalEmailClaims.EmailVerifiedClaimType).ToList())
        {
            identity.RemoveClaim(claim);
        }

        if (ReadVerified(user) == true)
        {
            identity.AddClaim(new Claim(ExternalEmailClaims.EmailVerifiedClaimType, "true"));
        }
    }
}
