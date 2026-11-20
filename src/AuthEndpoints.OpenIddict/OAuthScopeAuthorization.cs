using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Abstractions;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// Scope checks for code that authorizes inside services instead of on endpoints, such as MCP tool handlers.
/// They read only identities created from an access token by
/// <see cref="OAuthServerServiceCollectionExtensions.ValidationScheme"/>, so a cookie, Identity bearer, or JWT identity
/// never contributes scopes.
/// </summary>
public static class OAuthClaimsPrincipalExtensions
{
    /// <summary>
    /// Whether the principal has an identity from an OAuth access token issued by this server, that is, a client calling
    /// for the user. The request has to be authenticated with <c>ValidationScheme</c> for this to be <see langword="true"/>:
    /// a policy or endpoint that only reads the cookie never sees the token.
    /// </summary>
    public static bool IsOAuthDelegated(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return OAuthIdentities(principal).Any();
    }

    /// <summary>The scopes granted to the OAuth access token, or none when the principal has no OAuth identity.</summary>
    public static IReadOnlyList<string> GetOAuthScopes(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return OAuthIdentities(principal).SelectMany(identity => identity.GetScopes()).Distinct(StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// Whether the OAuth access token was granted <paramref name="scope"/>. <see langword="false"/> when the principal has
    /// no OAuth identity: check <see cref="IsOAuthDelegated"/> first in code that cookie users reach too.
    /// </summary>
    public static bool HasOAuthScope(this ClaimsPrincipal principal, string scope)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        var identities = OAuthIdentities(principal).ToList();
        return identities.Count > 0 && identities.All(identity => identity.HasScope(scope));
    }

    /// <summary>Authenticated identities that OpenIddict validation built from an access token.</summary>
    internal static IEnumerable<ClaimsIdentity> OAuthIdentities(ClaimsPrincipal principal)
        => principal.Identities.Where(identity => identity.IsAuthenticated
            && string.Equals(identity.GetTokenType(), OpenIddictConstants.TokenTypeIdentifiers.AccessToken, StringComparison.Ordinal));
}

/// <summary>
/// Requires every scope in <see cref="Scopes"/> on the caller's OAuth access token. With <see cref="OnlyWhenDelegated"/>,
/// a caller without an OAuth access token (a cookie, Identity bearer, or JWT user) passes, so the requirement can sit next
/// to an existing role policy on a route that cookie users reach too. A scope never widens what the user may do:
/// the route's other requirements still apply. Handles itself, so it needs no handler registration.
/// </summary>
public sealed class OAuthScopeRequirement : AuthorizationHandler<OAuthScopeRequirement>, IAuthorizationRequirement
{
    /// <param name="scopes">Scopes the token must hold. At least one.</param>
    /// <param name="onlyWhenDelegated">Pass callers without an OAuth access token instead of failing them.</param>
    public OAuthScopeRequirement(IEnumerable<string> scopes, bool onlyWhenDelegated = false)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        var list = scopes.ToList();
        if (list.Count == 0)
        {
            throw new ArgumentException("List at least one scope.", nameof(scopes));
        }

        foreach (var scope in list)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(scope, nameof(scopes));
        }

        Scopes = list.Distinct(StringComparer.Ordinal).ToList();
        OnlyWhenDelegated = onlyWhenDelegated;
    }

    /// <summary>Scopes the token must hold, all of them.</summary>
    public IReadOnlyList<string> Scopes { get; }

    /// <summary>Whether a caller without an OAuth access token passes.</summary>
    public bool OnlyWhenDelegated { get; }

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OAuthScopeRequirement requirement)
    {
        // Every OAuth identity must hold every scope, so one token's scopes never cover another identity.
        var identities = OAuthClaimsPrincipalExtensions.OAuthIdentities(context.User).ToList();
        if (identities.Count == 0
            ? requirement.OnlyWhenDelegated
            : identities.All(identity => requirement.Scopes.All(identity.HasScope)))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }

    public override string ToString()
        => $"{nameof(OAuthScopeRequirement)}: the OAuth access token needs the scopes {string.Join(", ", Scopes)}"
            + (OnlyWhenDelegated ? " (callers without one pass)." : ".");
}
