using Microsoft.AspNetCore.Authorization;
using OpenIddict.Abstractions;

namespace AuthEndpoints.OpenIddict;

/// <summary>Authorization policy helpers for APIs that validate tokens issued by this server.</summary>
public static class OAuthAuthorizationPolicyBuilderExtensions
{
    /// <summary>
    /// Authenticates with <see cref="OAuthServerServiceCollectionExtensions.ValidationScheme"/> and requires the
    /// access token's <c>aud</c> to contain <paramref name="audience"/>. Use one policy per resource when
    /// <see cref="OAuthServerOptions.AcceptedAudiences"/> lets this host accept more than one audience,
    /// so a token issued for one resource cannot call another.
    /// </summary>
    public static AuthorizationPolicyBuilder RequireOAuthAudience(this AuthorizationPolicyBuilder policy, string audience)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        return policy
            .AddAuthenticationSchemes(OAuthServerServiceCollectionExtensions.ValidationScheme)
            .RequireAuthenticatedUser()
            .RequireAssertion(context => context.User.HasAudience(audience));
    }
}
