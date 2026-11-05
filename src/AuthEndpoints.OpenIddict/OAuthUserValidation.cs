using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// Decides whether the user who approved a grant may still get tokens from it.
/// The default checks that the user exists, can sign in, is not locked out, and has the same security stamp.
/// </summary>
public interface IOAuthUserValidator
{
    /// <summary>The value stored in the grant at approval, compared on every later token request. Default: the security stamp.</summary>
    ValueTask<string?> GetStampAsync(string userId, CancellationToken cancellationToken);

    /// <summary>Returns <see langword="false"/> to reject the token request and revoke the grant.</summary>
    ValueTask<bool> IsValidAsync(string userId, string? stamp, CancellationToken cancellationToken);
}

/// <summary>
/// Default <see cref="IOAuthUserValidator"/>. A changed password, reset authenticator, removed login, lockout,
/// or deleted account stops the grant at the next code exchange or refresh.
/// </summary>
public sealed class IdentityOAuthUserValidator<TUser>(UserManager<TUser> users, IServiceProvider services) : IOAuthUserValidator
    where TUser : class
{
    public async ValueTask<string?> GetStampAsync(string userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId);
        return user is not null && users.SupportsUserSecurityStamp ? await users.GetSecurityStampAsync(user) : null;
    }

    public async ValueTask<bool> IsValidAsync(string userId, string? stamp, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null)
        {
            return false;
        }

        if (users.SupportsUserLockout && await users.IsLockedOutAsync(user))
        {
            return false;
        }

        if (services.GetService<SignInManager<TUser>>() is { } signIn && !await signIn.CanSignInAsync(user))
        {
            return false;
        }

        if (users.SupportsUserSecurityStamp
            && !string.Equals(stamp ?? string.Empty, await users.GetSecurityStampAsync(user) ?? string.Empty, StringComparison.Ordinal))
        {
            return false;
        }

        return true;
    }
}

/// <summary>Adds the approving user's id and stamp to the grant. They stay in the code and refresh token only.</summary>
internal static class OAuthGrantClaims
{
    public static async Task AddAsync(System.Security.Claims.ClaimsPrincipal principal, string userId, IOAuthUserValidator validator, CancellationToken cancellationToken)
    {
        principal.SetClaim(OAuthServerConstants.UserIdClaim, userId);
        principal.SetClaim(OAuthServerConstants.UserStampClaim, await validator.GetStampAsync(userId, cancellationToken));
        foreach (var claim in principal.Claims)
        {
            if (claim.Type is OAuthServerConstants.UserIdClaim or OAuthServerConstants.UserStampClaim)
            {
                claim.SetDestinations([]);
            }
        }
    }
}

/// <summary>
/// Runs at the token endpoint for code and refresh grants. Rejects with <c>invalid_grant</c> and revokes the
/// authorization when the approving user is no longer allowed to sign in.
/// </summary>
internal sealed class RevalidateGrantUser(
    IOAuthUserValidator validator,
    IOpenIddictAuthorizationManager authorizations,
    IOpenIddictTokenManager tokens,
    IOptions<OAuthServerOptions> options) : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessSignInContext>
{
    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignInContext context)
    {
        if (!options.Value.RevalidateUser
            || context.EndpointType != OpenIddictServerEndpointType.Token
            || context.Transaction.GetHttpRequest() is null
            || context.Request is not { } request
            || !(request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType()))
        {
            return;
        }

        var userId = context.Principal?.GetClaim(OAuthServerConstants.UserIdClaim);
        if (string.IsNullOrEmpty(userId))
        {
            return;
        }

        var stamp = context.Principal!.GetClaim(OAuthServerConstants.UserStampClaim);
        if (await validator.IsValidAsync(userId, stamp, context.CancellationToken))
        {
            return;
        }

        if (context.Principal!.GetAuthorizationId() is { Length: > 0 } authorizationId)
        {
            await tokens.RevokeByAuthorizationIdAsync(authorizationId, context.CancellationToken);
            if (await authorizations.FindByIdAsync(authorizationId, context.CancellationToken) is { } authorization)
            {
                await authorizations.TryRevokeAsync(authorization, context.CancellationToken);
            }
        }

        context.Reject(OpenIddictConstants.Errors.InvalidGrant, "The user can no longer use this grant.");
    }
}
