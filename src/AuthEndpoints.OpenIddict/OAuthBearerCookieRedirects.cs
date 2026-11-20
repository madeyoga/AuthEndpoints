using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// A token caller that a policy refuses on a route that also reads the sign-in cookie would otherwise get the cookie's
/// redirect to the login or access-denied page (<c>302</c>). For a request with <c>Authorization: Bearer</c>, answer
/// <c>401</c> or <c>403</c> instead. Every other request goes to the cookie's own events, the host's included.
/// Applies to the Identity application cookie and to <see cref="OAuthServerOptions.AuthenticationScheme"/>.
/// Off with <see cref="OAuthServerOptions.BearerRequestsSkipCookieRedirects"/>.
/// </summary>
internal sealed class OAuthBearerCookieRedirects(IOptions<OAuthServerOptions> oauth) : IPostConfigureOptions<CookieAuthenticationOptions>
{
    public void PostConfigure(string? name, CookieAuthenticationOptions options)
    {
        if (Settings() is not { BearerRequestsSkipCookieRedirects: true } settings
            || !(string.Equals(name, IdentityConstants.ApplicationScheme, StringComparison.Ordinal)
                || string.Equals(name, settings.AuthenticationScheme, StringComparison.Ordinal)))
        {
            return;
        }

        var events = options.EventsType is { } eventsType
            ? ForwardTo(eventsType)
            : options.Events ??= new CookieAuthenticationEvents();
        options.EventsType = null;
        options.Events = events;

        var login = events.OnRedirectToLogin;
        var denied = events.OnRedirectToAccessDenied;
        events.OnRedirectToLogin = context => IsBearer(context.Request) ? Status(context, StatusCodes.Status401Unauthorized) : login(context);
        events.OnRedirectToAccessDenied = context => IsBearer(context.Request) ? Status(context, StatusCodes.Status403Forbidden) : denied(context);
    }

    /// <summary>A request that carries <c>Authorization: Bearer …</c>, whatever issued the token.</summary>
    internal static bool IsBearer(HttpRequest request)
        => request.Headers.Authorization.ToString() is { Length: > 7 } value
            && value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);

    private static Task Status(RedirectContext<CookieAuthenticationOptions> context, int status)
    {
        context.Response.StatusCode = status;
        return Task.CompletedTask;
    }

    // The cookie handler ignores Events when EventsType is set. Forward every callback to the host's events type,
    // resolved per request, so the redirects can be wrapped without replacing the host's events.
    private static CookieAuthenticationEvents ForwardTo(Type eventsType)
    {
        CookieAuthenticationEvents Resolve(HttpContext http) =>
            (CookieAuthenticationEvents)http.RequestServices.GetRequiredService(eventsType);

        return new CookieAuthenticationEvents
        {
            OnValidatePrincipal = c => Resolve(c.HttpContext).ValidatePrincipal(c),
            OnCheckSlidingExpiration = c => Resolve(c.HttpContext).CheckSlidingExpiration(c),
            OnSigningIn = c => Resolve(c.HttpContext).SigningIn(c),
            OnSignedIn = c => Resolve(c.HttpContext).SignedIn(c),
            OnSigningOut = c => Resolve(c.HttpContext).SigningOut(c),
            OnRedirectToLogin = c => Resolve(c.HttpContext).RedirectToLogin(c),
            OnRedirectToAccessDenied = c => Resolve(c.HttpContext).RedirectToAccessDenied(c),
            OnRedirectToLogout = c => Resolve(c.HttpContext).RedirectToLogout(c),
            OnRedirectToReturnUrl = c => Resolve(c.HttpContext).RedirectToReturnUrl(c),
        };
    }

    private OAuthServerOptions? Settings()
    {
        try
        {
            return oauth.Value;
        }
        catch (OptionsValidationException)
        {
            // Startup validation reports the problem. Do not fail cookie setup for it.
            return null;
        }
    }
}
