using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// <c>GET /connect/authorize</c>. OpenIddict has already validated the client, redirect URI, response type,
/// PKCE, and requested scopes when this runs (passthrough mode). This adds the resource and default-scope rules,
/// sends signed-out users to the host login page, and stores a pending consent for the host consent page.
/// </summary>
internal static class OAuthAuthorizeEndpoint<TContext, TKey>
    where TContext : DbContext
    where TKey : IEquatable<TKey>
{
    private const int MaxStateLength = 2048;
    private const int MaxChallengeLength = 128;
    private const int MaxScopeLength = 256;
    private const int MaxRedirectLength = 2048;
    private const int MaxClientNameLength = 200;

    public static async Task<IResult> HandleAsync(
        HttpContext http,
        TContext db,
        IOpenIddictApplicationManager applications,
        IOAuthDeveloperAppGate developerApps,
        IOptions<OAuthServerOptions> options,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var request = http.GetOpenIddictServerRequest();
        if (request is null || string.IsNullOrEmpty(request.ClientId) || string.IsNullOrEmpty(request.RedirectUri))
        {
            return Results.BadRequest();
        }

        var settings = options.Value;
        var application = await applications.FindByClientIdAsync(request.ClientId, cancellationToken);
        if (application is null)
        {
            return Reject(OpenIddictConstants.Errors.InvalidClient, "Unknown client.");
        }

        if (!await developerApps.AllowsAsync(application, cancellationToken))
        {
            return Reject(OpenIddictConstants.Errors.UnauthorizedClient, "This application is not active.");
        }

        if (!string.Equals(request.CodeChallengeMethod, OpenIddictConstants.CodeChallengeMethods.Sha256, StringComparison.Ordinal)
            || string.IsNullOrEmpty(request.CodeChallenge))
        {
            return Reject(OpenIddictConstants.Errors.InvalidRequest, "code_challenge with code_challenge_method S256 is required.");
        }

        if ((request.State?.Length ?? 0) > MaxStateLength
            || request.CodeChallenge.Length > MaxChallengeLength
            || request.RedirectUri.Length > MaxRedirectLength)
        {
            return Reject(OpenIddictConstants.Errors.InvalidRequest, "state, code_challenge, or redirect_uri is too long.");
        }

        var resources = request.GetResources();
        string resource;
        if (resources.IsDefaultOrEmpty)
        {
            resource = settings.Audience!;
        }
        else if (resources.Length > 1)
        {
            return Reject(OpenIddictConstants.Errors.InvalidTarget, "Only one resource can be requested.");
        }
        else
        {
            resource = resources[0];
        }

        if (!settings.AllResources().Contains(resource, StringComparer.Ordinal))
        {
            return Reject(OpenIddictConstants.Errors.InvalidTarget, "The resource is not served by this authorization server.");
        }

        if (!settings.IgnoreResourcePermissions
            && !await applications.HasPermissionAsync(application, OpenIddictConstants.Permissions.Prefixes.Resource + resource, cancellationToken))
        {
            return Reject(OpenIddictConstants.Errors.InvalidTarget, "This client may not request the resource.");
        }

        var scopes = await GrantedScopesAsync(request, application, applications, settings, cancellationToken);
        if (scopes.Error is { } scopeError)
        {
            return Reject(OpenIddictConstants.Errors.InvalidScope, scopeError);
        }

        var scope = string.Join(' ', scopes.Granted);
        if (scope.Length > MaxScopeLength)
        {
            return Reject(OpenIddictConstants.Errors.InvalidScope, "Too many scopes.");
        }

        var result = await http.AuthenticateAsync(settings.AuthenticationScheme);
        var userId = result.Succeeded ? result.Principal?.FindFirst(settings.UserIdClaimType)?.Value : null;
        var promptNone = request.HasPromptValue(OpenIddictConstants.PromptValues.None);
        if (string.IsNullOrEmpty(userId))
        {
            if (promptNone)
            {
                return Reject(OpenIddictConstants.Errors.LoginRequired, "The user is not signed in.");
            }

            // The return URL is this request, rebuilt from the server's own path. It never comes from the client.
            var returnUrl = http.Request.PathBase + http.Request.Path + http.Request.QueryString;
            return Results.Redirect(QueryHelpers.AddQueryString(settings.LoginUrl!, settings.LoginReturnUrlParameter, returnUrl));
        }

        if (promptNone)
        {
            return Reject(OpenIddictConstants.Errors.ConsentRequired, "The user must approve this client.");
        }

        if (!OAuthConsentService<TContext, TKey>.TryKey(userId, out var key))
        {
            throw new InvalidOperationException(
                $"The '{settings.UserIdClaimType}' claim is not a valid {typeof(TKey).Name} user id.");
        }

        var name = await applications.GetDisplayNameAsync(application, cancellationToken);
        name = string.IsNullOrWhiteSpace(name) ? OAuthServerConstants.FallbackClientName : name.Trim();
        if (name.Length > MaxClientNameLength)
        {
            name = name[..MaxClientNameLength];
        }

        var now = clock.GetUtcNow();
        var row = new OAuthRequest<TKey>
        {
            UserId = key,
            ClientId = request.ClientId,
            ClientName = name,
            RedirectUri = request.RedirectUri,
            RedirectHost = OAuthRedirects.Host(request.RedirectUri),
            CodeChallenge = request.CodeChallenge,
            Scope = scope,
            State = string.IsNullOrEmpty(request.State) ? null : request.State,
            Resource = resource,
            CreatedAt = now,
            ExpiresAt = now + settings.ConsentLifetime,
        };
        db.Set<OAuthRequest<TKey>>().Add(row);
        await db.SaveChangesAsync(cancellationToken);
        return Results.Redirect(QueryHelpers.AddQueryString(
            settings.ConsentUrl!, settings.ConsentRequestParameter, row.Id.ToString()));
    }

    private static async Task<(List<string> Granted, string? Error)> GrantedScopesAsync(
        OpenIddictRequest request,
        object application,
        IOpenIddictApplicationManager applications,
        OAuthServerOptions settings,
        CancellationToken cancellationToken)
    {
        var known = settings.AllScopes().ToHashSet(StringComparer.Ordinal);
        var requested = request.GetScopes();
        var granted = new List<string>();
        if (!requested.IsDefaultOrEmpty)
        {
            foreach (var item in requested)
            {
                if (!known.Contains(item))
                {
                    return ([], $"The scope '{item}' is not supported.");
                }

                if (!granted.Contains(item))
                {
                    granted.Add(item);
                }
            }
        }
        else
        {
            foreach (var item in settings.DefaultScopes)
            {
                if (!granted.Contains(item) && await AllowedAsync(item))
                {
                    granted.Add(item);
                }
            }
        }

        if (settings.AlwaysIssueRefreshToken
            && !granted.Contains(OAuthServerConstants.OfflineAccessScope)
            && await AllowedAsync(OAuthServerConstants.OfflineAccessScope))
        {
            granted.Add(OAuthServerConstants.OfflineAccessScope);
        }

        return (granted, null);

        async Task<bool> AllowedAsync(string item)
        {
            if (item == OAuthServerConstants.OfflineAccessScope)
            {
                return await applications.HasPermissionAsync(
                    application, OpenIddictConstants.Permissions.GrantTypes.RefreshToken, cancellationToken);
            }

            return await applications.HasPermissionAsync(
                application, OpenIddictConstants.Permissions.Prefixes.Scope + item, cancellationToken);
        }
    }

    /// <summary>Lets OpenIddict write the error response, with <c>iss</c>, to the validated redirect URI.</summary>
    private static IResult Reject(string error, string description)
        => Results.Forbid(
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
            }),
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
}
