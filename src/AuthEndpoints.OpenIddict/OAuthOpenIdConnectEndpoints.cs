using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// <c>GET|POST /connect/userinfo</c>. OpenIddict has already validated the access token (passthrough mode).
/// Returns <c>sub</c>, plus <c>email</c> and <c>email_verified</c> with the <c>email</c> scope, read from the user each time.
/// </summary>
internal static class OAuthUserInfoEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext http,
        IOpenIddictAuthorizationManager authorizations,
        IOAuthUserProfiles profiles,
        CancellationToken cancellationToken)
    {
        var principal = (await http.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
        if (principal?.GetClaim(OpenIddictConstants.Claims.Subject) is not { Length: > 0 } subject)
        {
            return Challenge(OpenIddictConstants.Errors.InvalidToken, "The access token is not valid.");
        }

        if (!principal.HasScope(OAuthServerConstants.OpenIdScope))
        {
            return Challenge(OpenIddictConstants.Errors.InsufficientScope, "The access token does not have the openid scope.");
        }

        string? userId = null;
        OAuthUserProfile? profile = null;
        if (principal.HasScope(OAuthServerConstants.EmailScope))
        {
            userId = await OAuthAuthorizationUser.FindAsync(authorizations, principal.GetAuthorizationId(), cancellationToken);
            if (userId is not null)
            {
                profile = await profiles.FindAsync(userId, cancellationToken);
                if (profile is null)
                {
                    return Challenge(OpenIddictConstants.Errors.InvalidToken, "The user no longer exists.");
                }
            }
        }

        return Results.Ok(OAuthIdentityClaims.UserInfo(subject, userId, principal, profile));
    }

    private static IResult Challenge(string error, string description)
        => Results.Challenge(
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
            }),
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
}

/// <summary>
/// <c>GET|POST /connect/logout</c> (OpenID Connect RP-initiated logout). OpenIddict has already validated
/// <c>id_token_hint</c>, <c>client_id</c>, and that <c>post_logout_redirect_uri</c> is registered for the client.
/// <list type="bullet">
/// <item>A <c>post_logout_redirect_uri</c> must name its client (<c>client_id</c> or <c>id_token_hint</c>), so it is
/// matched against that client's registered URIs only, never against any client's.</item>
/// <item>A signed-in user is signed out only when <c>id_token_hint</c> was issued to that user. Otherwise the browser goes
/// to <see cref="OAuthServerOptions.LogoutUrl"/> to confirm, or the request is refused. A third-party page cannot sign
/// the user out with a link.</item>
/// <item>A signed-out user is sent straight to the validated <c>post_logout_redirect_uri</c>.</item>
/// </list>
/// </summary>
internal static class OAuthEndSessionEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext http,
        IOpenIddictAuthorizationManager authorizations,
        IOpenIddictApplicationManager applications,
        IOAuthDeveloperAppGate developerApps,
        IAuthenticationSchemeProvider schemes,
        IOptions<OAuthServerOptions> options,
        CancellationToken cancellationToken)
    {
        var request = http.GetOpenIddictServerRequest();
        if (request is null)
        {
            return Results.BadRequest();
        }

        var settings = options.Value;
        var hint = string.IsNullOrEmpty(request.IdTokenHint)
            ? null
            : (await http.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
        if (!string.IsNullOrEmpty(request.PostLogoutRedirectUri))
        {
            var clientId = !string.IsNullOrEmpty(request.ClientId)
                ? request.ClientId
                : hint?.GetPresenters().FirstOrDefault() ?? hint?.GetAudiences().FirstOrDefault();
            if (string.IsNullOrEmpty(clientId))
            {
                return Reject(OpenIddictConstants.Errors.InvalidRequest, "post_logout_redirect_uri requires client_id or id_token_hint.");
            }

            if (await applications.FindByClientIdAsync(clientId, cancellationToken) is not { } application
                || !await developerApps.AllowsAsync(application, cancellationToken))
            {
                return Reject(OpenIddictConstants.Errors.UnauthorizedClient, "This application is not active.");
            }
        }

        var signedIn = await http.AuthenticateAsync(settings.AuthenticationScheme);
        var userId = signedIn.Succeeded ? signedIn.Principal?.FindFirst(settings.UserIdClaimType)?.Value : null;
        if (!string.IsNullOrEmpty(userId))
        {
            var approvedBy = hint is null
                ? null
                : await OAuthAuthorizationUser.FindAsync(authorizations, hint.GetAuthorizationId(), cancellationToken);
            if (!string.Equals(approvedBy, userId, StringComparison.Ordinal))
            {
                if (string.IsNullOrEmpty(settings.LogoutUrl))
                {
                    return Reject(
                        OpenIddictConstants.Errors.InvalidRequest,
                        "Sign-out requires an id_token_hint issued to the signed-in user.");
                }

                // The return URL is this request, rebuilt on the server's own path. The page signs the user out and returns here.
                var returnUrl = QueryHelpers.AddQueryString(
                    (http.Request.PathBase + http.Request.Path).ToString(),
                    request.GetParameters().Select(parameter =>
                        new KeyValuePair<string, string?>(parameter.Key, (string?)parameter.Value)));
                return Results.Redirect(QueryHelpers.AddQueryString(settings.LogoutUrl, settings.LoginReturnUrlParameter, returnUrl));
            }

            await SignOutAsync(http, schemes, settings.AuthenticationScheme);
        }

        // OpenIddict redirects to the validated post_logout_redirect_uri, with state, or answers 200 without one.
        return Results.SignOut(authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    /// <summary>Signs out the cookie scheme, and the Identity external and two-factor cookies as <c>SignInManager.SignOutAsync</c> does.</summary>
    private static async Task SignOutAsync(HttpContext http, IAuthenticationSchemeProvider schemes, string scheme)
    {
        await http.SignOutAsync(scheme);
        if (scheme != IdentityConstants.ApplicationScheme)
        {
            return;
        }

        foreach (var other in new[] { IdentityConstants.ExternalScheme, IdentityConstants.TwoFactorUserIdScheme })
        {
            if (await schemes.GetSchemeAsync(other) is not null)
            {
                await http.SignOutAsync(other);
            }
        }
    }

    /// <summary>An error shown to the user. Never redirected: the client or its redirect could not be trusted.</summary>
    private static IResult Reject(string error, string description)
        => Results.Json(new OAuthProtocolError(error, description), statusCode: StatusCodes.Status400BadRequest);
}
