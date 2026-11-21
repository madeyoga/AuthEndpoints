using System.Security.Claims;
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

    /// <summary>
    /// Called at every code exchange and refresh. Returns <see langword="false"/> to reject the token request and revoke
    /// the grant. Override it to read the grant's own claims, such as an organization a principal factory bound at consent.
    /// The default calls <see cref="IsValidAsync"/> with the user id and stored stamp, so existing validators keep working.
    /// </summary>
    ValueTask<bool> ValidateAsync(OAuthUserValidationContext context, CancellationToken cancellationToken)
        => IsValidAsync(context.UserId, context.SecurityStamp, cancellationToken);
}

/// <summary>What <see cref="IOAuthUserValidator.ValidateAsync"/> knows about the token request and its grant.</summary>
public sealed class OAuthUserValidationContext
{
    /// <summary>The Identity id of the user who approved the grant, even when a principal factory chose another <c>sub</c>.</summary>
    public required string UserId { get; init; }

    /// <summary>The value <see cref="IOAuthUserValidator.GetStampAsync"/> returned at approval.</summary>
    public string? SecurityStamp { get; init; }

    /// <summary>
    /// The grant: the principal stored in the authorization code or refresh token, with the claims the principal factory
    /// set at consent (such as <c>sub</c> or an organization claim). This package's internal claims (the approving user
    /// id and stamp) and OpenIddict's private claims (<c>oi_*</c>) are removed; use <see cref="UserId"/>,
    /// <see cref="SecurityStamp"/>, <see cref="Scopes"/>, and <see cref="AuthorizationId"/> instead. A copy: changes are ignored.
    /// </summary>
    public required ClaimsPrincipal Grant { get; init; }

    /// <summary><c>authorization_code</c> or <c>refresh_token</c>.</summary>
    public required string GrantType { get; init; }

    /// <summary>The client's <c>client_id</c>.</summary>
    public string? ClientId { get; init; }

    /// <summary>The OpenIddict authorization (grant) id, when there is one.</summary>
    public string? AuthorizationId { get; init; }

    /// <summary>The granted scopes.</summary>
    public IReadOnlyList<string> Scopes { get; init; } = [];

    /// <summary>A copy of <paramref name="principal"/> without this package's internal claims or OpenIddict's private ones.</summary>
    internal static ClaimsPrincipal PublicGrant(ClaimsPrincipal principal)
        => principal.Clone(claim => claim.Type is not (OAuthServerConstants.UserIdClaim or OAuthServerConstants.UserStampClaim)
            && !claim.Type.StartsWith("oi_", StringComparison.Ordinal));
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
/// Runs at the token endpoint for code and refresh grants. Rejects with <c>unauthorized_client</c> when the client is
/// a developer app that is pending approval, disabled, or whose row is gone (its owner was deleted).
/// </summary>
internal sealed class RequireActiveDeveloperApp(
    IOpenIddictApplicationManager applications,
    IOAuthDeveloperAppGate gate) : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessSignInContext>
{
    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignInContext context)
    {
        if (context.EndpointType != OpenIddictServerEndpointType.Token
            || context.Request is not { ClientId: { Length: > 0 } clientId } request
            || !(request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType()))
        {
            return;
        }

        if (await applications.FindByClientIdAsync(clientId, context.CancellationToken) is { } application
            && !await gate.AllowsAsync(application, context.CancellationToken))
        {
            context.Reject(OpenIddictConstants.Errors.UnauthorizedClient, "This application is not active.");
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
    IOpenIddictApplicationManager applications,
    OAuthServerEventDispatcher events,
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

        var principal = context.Principal!;
        var validation = new OAuthUserValidationContext
        {
            UserId = userId,
            SecurityStamp = principal.GetClaim(OAuthServerConstants.UserStampClaim),
            Grant = OAuthUserValidationContext.PublicGrant(principal),
            GrantType = request.GrantType!,
            ClientId = request.ClientId,
            AuthorizationId = principal.GetAuthorizationId(),
            Scopes = principal.GetScopes().ToArray(),
        };
        if (await validator.ValidateAsync(validation, context.CancellationToken))
        {
            return;
        }

        var authorizationId = context.Principal!.GetAuthorizationId();
        if (authorizationId is { Length: > 0 })
        {
            await tokens.RevokeByAuthorizationIdAsync(authorizationId, context.CancellationToken);
            if (await authorizations.FindByIdAsync(authorizationId, context.CancellationToken) is { } authorization)
            {
                await authorizations.TryRevokeAsync(authorization, context.CancellationToken);
            }
        }

        if (events.HasSubscribers)
        {
            string? kind = null;
            if (request.ClientId is { Length: > 0 } clientId
                && await applications.FindByClientIdAsync(clientId, context.CancellationToken) is { } application)
            {
                kind = OAuthClientKinds.From(await applications.GetSettingsAsync(application, context.CancellationToken));
            }

            await events.RaiseAsync(new OAuthServerEvent(OAuthServerEventType.GrantRefused, events.Now)
            {
                UserId = userId,
                ClientId = request.ClientId,
                ClientKind = kind,
                AuthorizationId = authorizationId,
                Scopes = principal.GetScopes().ToArray(),
                Resource = principal.GetResources().FirstOrDefault(),
                GrantType = request.GrantType,
            }, context.CancellationToken);
        }

        context.Reject(OpenIddictConstants.Errors.InvalidGrant, "The user can no longer use this grant.");
    }
}
