using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace AuthEndpoints.OpenIddict;

/// <summary>The Identity user fields that OpenID Connect releases.</summary>
internal sealed record OAuthUserProfile(string? Email, bool EmailVerified);

/// <summary>Reads <see cref="OAuthUserProfile"/> for a user id. <see langword="null"/> when the user does not exist.</summary>
internal interface IOAuthUserProfiles
{
    ValueTask<OAuthUserProfile?> FindAsync(string userId, CancellationToken cancellationToken);
}

internal sealed class IdentityOAuthUserProfiles<TUser>(UserManager<TUser> users) : IOAuthUserProfiles
    where TUser : class
{
    public async ValueTask<OAuthUserProfile?> FindAsync(string userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null)
        {
            return null;
        }

        if (!users.SupportsUserEmail)
        {
            return new OAuthUserProfile(null, false);
        }

        var email = await users.GetEmailAsync(user);
        return new OAuthUserProfile(
            string.IsNullOrEmpty(email) ? null : email,
            !string.IsNullOrEmpty(email) && await users.IsEmailConfirmedAsync(user));
    }
}

/// <summary>Claims that OpenID Connect adds to the token principal. They go to the ID token only, never to access tokens.</summary>
internal static class OAuthIdentityClaims
{
    public const string EmailVerified = "email_verified";

    /// <summary>
    /// Adds <c>amr</c>, and with the <c>email</c> scope <c>email</c> and <c>email_verified</c>, to the ID token.
    /// A claim the principal factory already set is kept as it is. The Identity user's email is added only when
    /// <c>sub</c> is that user, so a factory that issues tokens for another subject does not get the user's email attached.
    /// </summary>
    public static void Add(
        ClaimsPrincipal principal,
        string userId,
        IReadOnlyCollection<string> scopes,
        string? authenticationMethods,
        OAuthUserProfile? profile)
    {
        var methods = OAuthScopes.Split(authenticationMethods);
        if (methods.Length > 0 && !principal.HasClaim(claim => claim.Type == OAuthAuthenticationMethods.ClaimType))
        {
            // RFC 8176: amr is a JSON array, even with one value.
            var claim = new Claim(
                OAuthAuthenticationMethods.ClaimType,
                JsonSerializer.Serialize(methods),
                Microsoft.IdentityModel.JsonWebTokens.JsonClaimValueTypes.JsonArray);
            ((ClaimsIdentity)principal.Identity!).AddClaim(claim);
            IdentityTokenOnly(principal, OAuthAuthenticationMethods.ClaimType);
        }

        if (!scopes.Contains(OAuthServerConstants.EmailScope)
            || profile?.Email is not { } email
            || !string.Equals(principal.GetClaim(OpenIddictConstants.Claims.Subject), userId, StringComparison.Ordinal)
            || principal.HasClaim(claim => claim.Type is OpenIddictConstants.Claims.Email or EmailVerified))
        {
            return;
        }

        principal.SetClaim(OpenIddictConstants.Claims.Email, email);
        principal.SetClaim(EmailVerified, profile.EmailVerified);
        IdentityTokenOnly(principal, OpenIddictConstants.Claims.Email);
        IdentityTokenOnly(principal, EmailVerified);
    }

    /// <summary>The userinfo response: <c>sub</c>, and the email claims under the same rules as the ID token.</summary>
    public static Dictionary<string, object> UserInfo(string subject, string? userId, ClaimsPrincipal accessToken, OAuthUserProfile? profile)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [OpenIddictConstants.Claims.Subject] = subject,
        };
        if (accessToken.HasScope(OAuthServerConstants.EmailScope)
            && string.Equals(subject, userId, StringComparison.Ordinal)
            && profile?.Email is { } email)
        {
            claims[OpenIddictConstants.Claims.Email] = email;
            claims[EmailVerified] = profile.EmailVerified;
        }

        return claims;
    }

    private static void IdentityTokenOnly(ClaimsPrincipal principal, string type)
    {
        foreach (var claim in principal.FindAll(type))
        {
            claim.SetDestinations(OpenIddictConstants.Destinations.IdentityToken);
        }
    }
}

/// <summary>
/// Stores the approving user's id on the OpenIddict authorization, so userinfo and logout can find the user
/// from an access token or an <c>id_token_hint</c>. The id never goes into a token a client can read.
/// </summary>
internal static class OAuthAuthorizationUser
{
    public static async Task SetAsync(
        IOpenIddictAuthorizationManager authorizations, string authorizationId, string userId, CancellationToken cancellationToken)
    {
        var authorization = await authorizations.FindByIdAsync(authorizationId, cancellationToken)
            ?? throw new InvalidOperationException("The authorization was not stored.");
        var descriptor = new OpenIddictAuthorizationDescriptor();
        await authorizations.PopulateAsync(descriptor, authorization, cancellationToken);
        descriptor.Properties[OAuthServerConstants.AuthorizationUserProperty] = JsonSerializer.SerializeToElement(userId);
        await authorizations.UpdateAsync(authorization, descriptor, cancellationToken);
    }

    /// <summary>The approving user's id, or <see langword="null"/> for an unknown authorization or one stored before OpenID Connect was on.</summary>
    public static async Task<string?> FindAsync(
        IOpenIddictAuthorizationManager authorizations, string? authorizationId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(authorizationId)
            || await authorizations.FindByIdAsync(authorizationId, cancellationToken) is not { } authorization)
        {
            return null;
        }

        var properties = await authorizations.GetPropertiesAsync(authorization, cancellationToken);
        return properties.TryGetValue(OAuthServerConstants.AuthorizationUserProperty, out var value)
            && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
    }
}
