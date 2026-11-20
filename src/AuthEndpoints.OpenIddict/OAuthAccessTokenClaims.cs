using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthEndpoints.OpenIddict;

/// <summary>Reads a user's Identity roles for <see cref="OAuthAccessTokenClaimOptions.Roles"/>.</summary>
internal interface IOAuthUserRoles
{
    /// <summary>Whether the user store keeps roles (<c>AddRoles&lt;TRole&gt;()</c>).</summary>
    bool Supported { get; }

    /// <summary>The user's roles, or none when the user does not exist or the store has no roles.</summary>
    ValueTask<IReadOnlyList<string>> GetRolesAsync(string userId, CancellationToken cancellationToken);
}

internal sealed class IdentityOAuthUserRoles<TUser>(UserManager<TUser> users) : IOAuthUserRoles
    where TUser : class
{
    public bool Supported => users.SupportsUserRole;

    public async ValueTask<IReadOnlyList<string>> GetRolesAsync(string userId, CancellationToken cancellationToken)
    {
        if (!users.SupportsUserRole || await users.FindByIdAsync(userId) is not { } user)
        {
            return [];
        }

        return (await users.GetRolesAsync(user)).ToList();
    }
}

/// <summary>
/// Runs at the token endpoint for code and refresh grants, after OpenIddict has built the access token principal and
/// before it generates the token. Adds the approving user's roles and user id claims to the access token only, so they
/// never reach the code, the refresh token, or the ID token, and each refresh reads them again.
/// </summary>
internal sealed class AttachAccessTokenUserClaims(
    IOptions<OAuthServerOptions> options,
    IOptions<IdentityOptions> identityOptions,
    IOAuthUserRoles roles) : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessSignInContext>
{
    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignInContext context)
    {
        var settings = options.Value.AccessTokenClaims;
        if (!(settings.Roles || settings.UserId)
            || context.EndpointType != OpenIddictServerEndpointType.Token
            || context.Request is not { } request
            || !(request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
            || context.AccessTokenPrincipal is not { Identity: ClaimsIdentity access } accessPrincipal
            || context.Principal is not { } grant)
        {
            return;
        }

        // Only for the approving user. A principal factory that issues tokens for another subject keeps its own claims.
        var userId = grant.GetClaim(OAuthServerConstants.UserIdClaim);
        var subject = grant.GetClaim(OpenIddictConstants.Claims.Subject);
        if (string.IsNullOrEmpty(userId) || !string.Equals(userId, subject, StringComparison.Ordinal))
        {
            return;
        }

        if (settings.UserId)
        {
            foreach (var type in UserIdClaimTypes())
            {
                accessPrincipal.SetClaim(type, userId);
            }
        }

        if (settings.Roles)
        {
            foreach (var role in await roles.GetRolesAsync(userId, context.CancellationToken))
            {
                if (!access.HasClaim(OpenIddictConstants.Claims.Role, role))
                {
                    access.AddClaim(new Claim(OpenIddictConstants.Claims.Role, role));
                }
            }
        }
    }

    private IEnumerable<string> UserIdClaimTypes()
        => new[] { ClaimTypes.NameIdentifier, options.Value.UserIdClaimType, identityOptions.Value.ClaimsIdentity.UserIdClaimType }
            .Where(type => !string.IsNullOrWhiteSpace(type) && !IsReserved(type))
            .Distinct(StringComparer.Ordinal);

    /// <summary><c>sub</c> is already there, and grant and OpenIddict private claims must never be overwritten.</summary>
    private static bool IsReserved(string type)
        => type is OpenIddictConstants.Claims.Subject or OAuthServerConstants.UserIdClaim or OAuthServerConstants.UserStampClaim
            || type.StartsWith("oi_", StringComparison.Ordinal);
}
