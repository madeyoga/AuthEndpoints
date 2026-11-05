using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// Which route groups <c>MapOAuthServer</c> maps, and where. Every part is on by default.
/// The authorization server routes are always mapped. Anonymous registration (<c>POST /connect/register</c>) and
/// protected resource metadata change the server's metadata too, so they stay in <see cref="OAuthServerOptions"/>
/// (<see cref="OAuthDynamicRegistrationOptions.Enabled"/>, <see cref="OAuthProtectedResourceOptions.Enabled"/>), off by default.
/// </summary>
public sealed class OAuthServerEndpointOptions
{
    /// <summary>
    /// Map the JSON consent API (<c>MapOAuthConsentEndpoints</c>). Default <see langword="true"/>.
    /// Turn it off when the host approves through <see cref="IOAuthConsentService"/> from its own routes.
    /// </summary>
    public bool ConsentApi { get; set; } = true;

    /// <summary>Prefix of the consent API. Default <c>/oauth</c>.</summary>
    public string ConsentPrefix { get; set; } = "/oauth";

    /// <summary>
    /// Map the developer app API (<c>MapOAuthDeveloperAppEndpoints</c>), where signed-in users register OAuth apps they own.
    /// Default <see langword="true"/>. Approval and limits are in <see cref="OAuthServerOptions.DeveloperApps"/>.
    /// </summary>
    public bool DeveloperApps { get; set; } = true;

    /// <summary>Prefix of the developer app API. Default <c>/oauth/apps</c>.</summary>
    public string DeveloperAppsPrefix { get; set; } = "/oauth/apps";
}

/// <summary>The route groups <c>MapOAuthServer</c> mapped, for conventions such as rate limiting or CORS.</summary>
public sealed class OAuthServerEndpoints
{
    internal OAuthServerEndpoints(RouteGroupBuilder? consent, RouteGroupBuilder? developerApps)
    {
        Consent = consent;
        DeveloperApps = developerApps;
    }

    /// <summary>The consent API group, or <see langword="null"/> when <see cref="OAuthServerEndpointOptions.ConsentApi"/> is off.</summary>
    public RouteGroupBuilder? Consent { get; }

    /// <summary>The developer app API group, or <see langword="null"/> when <see cref="OAuthServerEndpointOptions.DeveloperApps"/> is off.</summary>
    public RouteGroupBuilder? DeveloperApps { get; }
}
