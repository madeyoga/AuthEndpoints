using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace AuthEndpoints.OpenIddict;

/// <summary>What the host knows when it builds the token principal for an approved request.</summary>
public sealed class OAuthPrincipalContext
{
    public OAuthPrincipalContext(HttpContext httpContext, string userId, OAuthPendingRequest request)
    {
        HttpContext = httpContext;
        UserId = userId;
        Request = request;
    }

    public HttpContext HttpContext { get; }

    /// <summary>The signed-in user who approved the request.</summary>
    public string UserId { get; }

    public OAuthPendingRequest Request { get; }
}

/// <summary>
/// Builds the principal stored in the authorization code, access token, and refresh token.
/// The default puts the Identity user id in <c>sub</c>. Replace it to issue tokens for another subject,
/// for example a service account the user picked on the consent page.
/// </summary>
public interface IOAuthPrincipalFactory
{
    /// <summary>
    /// Returns the principal, or <see langword="null"/> to decline. A declined request is not consumed.
    /// The principal needs a <c>sub</c> claim. Claims without a destination are not copied into tokens.
    /// </summary>
    ValueTask<ClaimsPrincipal?> CreateAsync(OAuthPrincipalContext context, CancellationToken cancellationToken);
}

/// <summary>Default factory: <c>sub</c> is the signed-in Identity user id.</summary>
public sealed class UserIdOAuthPrincipalFactory : IOAuthPrincipalFactory
{
    public ValueTask<ClaimsPrincipal?> CreateAsync(OAuthPrincipalContext context, CancellationToken cancellationToken)
        => ValueTask.FromResult<ClaimsPrincipal?>(OAuthPrincipals.ForSubject(context.UserId));
}

/// <summary>Helpers for building a token principal.</summary>
public static class OAuthPrincipals
{
    /// <summary>A principal with only <c>sub</c>. Add claims and call <c>SetDestinations</c> for anything else the tokens need.</summary>
    public static ClaimsPrincipal ForSubject(string subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: OpenIddictConstants.Claims.Name,
            roleType: OpenIddictConstants.Claims.Role);
        identity.SetClaim(OpenIddictConstants.Claims.Subject, subject);
        return new ClaimsPrincipal(identity);
    }
}
