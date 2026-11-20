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

    /// <summary>
    /// Authenticates with <see cref="OAuthServerServiceCollectionExtensions.ValidationScheme"/> and requires every one of
    /// <paramref name="scopes"/> on the access token. A token missing one gets <c>403</c>. For routes only OAuth clients
    /// call, such as an MCP endpoint. Combine it with <see cref="RequireOAuthAudience"/> or <c>RequireRole</c>: a scope
    /// never widens what the user may do.
    /// </summary>
    public static AuthorizationPolicyBuilder RequireOAuthScope(this AuthorizationPolicyBuilder policy, params string[] scopes)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var requirement = new OAuthScopeRequirement(scopes);
        return policy
            .AddAuthenticationSchemes(OAuthServerServiceCollectionExtensions.ValidationScheme)
            .RequireAuthenticatedUser()
            .AddRequirements(requirement);
    }

    /// <summary>
    /// Requires every one of <paramref name="scopes"/> when the caller has an OAuth access token, and passes every other
    /// caller (cookie, Identity bearer, JWT). Adds no scheme and no authenticated-user check, so it sits next to an existing
    /// role policy on a route that cookie users and OAuth clients share. The policy has to authenticate with
    /// <see cref="OAuthServerServiceCollectionExtensions.ValidationScheme"/> too (for example
    /// <c>AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, ValidationScheme)</c>), or the token is never read.
    /// A request with both a cookie and a token still needs the scopes.
    /// </summary>
    public static AuthorizationPolicyBuilder RequireOAuthScopeWhenDelegated(this AuthorizationPolicyBuilder policy, params string[] scopes)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return policy.AddRequirements(new OAuthScopeRequirement(scopes, onlyWhenDelegated: true));
    }
}
