using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>
/// Token callers refused on routes that also read the Identity cookie get 401 or 403, not the cookie's 302 redirect.
/// </summary>
public sealed class OAuthBearerCookieRedirectTests
{
    [Fact]
    public async Task A_refused_token_caller_gets_403_and_a_browser_still_gets_the_redirect()
    {
        await using var host = await StartAsync(services: Defaults, map: Map);
        var (user, _) = await host.UserAsync("redirects");
        var (_, tokens) = await host.IssueAsync(user);

        // A handler that forbids with the default scheme (the cookie): a token caller gets 403, not a redirect.
        var forbidden = await CallAsync(host, tokens.AccessToken, "/shared/forbid");
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        Assert.Null(forbidden.Headers.Location);

        // A policy over both schemes refuses the token (no Admin role): 403, with no cookie redirect left in the response.
        var refused = await CallAsync(host, tokens.AccessToken, "/shared/admin");
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Null(refused.Headers.Location);

        // A browser without the header keeps the cookie's redirect.
        var browser = await user.GetAsync("/shared/forbid");
        Assert.Equal(HttpStatusCode.Found, browser.StatusCode);
        Assert.Contains("/Account/AccessDenied", browser.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_token_caller_on_a_cookie_only_route_gets_401_and_a_browser_still_gets_the_login_redirect()
    {
        await using var host = await StartAsync(services: Defaults, map: Map);

        // Any bearer header counts: the caller is an API client, not a browser that can follow a login redirect.
        var token = await CallAsync(host, "not-a-token-this-route-reads", "/cookie-only");
        Assert.Equal(HttpStatusCode.Unauthorized, token.StatusCode);
        Assert.Null(token.Headers.Location);

        using var anon = host.Client(cookies: false);
        var browser = await anon.GetAsync("/cookie-only");
        Assert.Equal(HttpStatusCode.Found, browser.StatusCode);
        Assert.Contains("/Account/Login", browser.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_hosts_own_cookie_events_still_run_for_other_requests()
    {
        await using var host = await StartAsync(
            services: services => services.ConfigureApplicationCookie(cookie =>
            {
                cookie.Events.OnRedirectToLogin = context => Teapot(context, "login");
                cookie.Events.OnRedirectToAccessDenied = context => Teapot(context, "denied");
            }),
            map: Map);
        var (user, _) = await host.UserAsync("custom");
        var (_, tokens) = await host.IssueAsync(user);

        var browser = await user.GetAsync("/shared/forbid");
        Assert.Equal((HttpStatusCode)418, browser.StatusCode);
        Assert.Equal("denied", browser.Headers.GetValues("X-Host-Event").Single());
        using var anon = host.Client(cookies: false);
        Assert.Equal("login", (await anon.GetAsync("/cookie-only")).Headers.GetValues("X-Host-Event").Single());

        var token = await CallAsync(host, tokens.AccessToken, "/shared/forbid");
        Assert.Equal(HttpStatusCode.Forbidden, token.StatusCode);
        Assert.False(token.Headers.Contains("X-Host-Event"));
    }

    [Fact]
    public async Task An_events_type_set_by_the_host_is_kept()
    {
        await using var host = await StartAsync(
            services: services =>
            {
                services.AddScoped<HostCookieEvents>();
                services.ConfigureApplicationCookie(cookie => cookie.EventsType = typeof(HostCookieEvents));
            },
            map: Map);
        var (user, _) = await host.UserAsync("events-type");
        var (_, tokens) = await host.IssueAsync(user);

        var browser = await user.GetAsync("/shared/forbid");
        Assert.Equal((HttpStatusCode)418, browser.StatusCode);
        Assert.Equal("events-type", browser.Headers.GetValues("X-Host-Event").Single());
        var token = await CallAsync(host, tokens.AccessToken, "/shared/forbid");
        Assert.Equal(HttpStatusCode.Forbidden, token.StatusCode);
        Assert.False(token.Headers.Contains("X-Host-Event"));
    }

    [Fact]
    public async Task It_can_be_turned_off()
    {
        await using var host = await StartAsync(options => options.BearerRequestsSkipCookieRedirects = false, Defaults, Map);
        var (user, _) = await host.UserAsync("off");
        var (_, tokens) = await host.IssueAsync(user);

        Assert.Equal(HttpStatusCode.Found, (await CallAsync(host, tokens.AccessToken, "/shared/forbid")).StatusCode);
        Assert.NotNull((await CallAsync(host, tokens.AccessToken, "/shared/admin")).Headers.Location);
        Assert.True(new OAuthServerOptions().BearerRequestsSkipCookieRedirects);
    }

    /// <summary>The cookie's out-of-the-box redirects (the shared test host answers 401 for login instead).</summary>
    private static void Defaults(IServiceCollection services)
        => services.ConfigureApplicationCookie(cookie => cookie.Events.OnRedirectToLogin = context =>
        {
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        });

    private static void Map(WebApplication app)
    {
        // A route that cookie users and token callers share, guarded by a role neither caller has.
        app.MapGet("/shared/admin", () => Results.Ok()).RequireAuthorization(policy => policy
            .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, OAuthServerServiceCollectionExtensions.ValidationScheme)
            .RequireRole("Admin"));
        // A route that reads the token, then refuses with the default (cookie) scheme, as Results.Forbid() does.
        app.MapGet("/shared/forbid", () => Results.Forbid()).RequireAuthorization(policy => policy
            .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, OAuthServerServiceCollectionExtensions.ValidationScheme)
            .RequireAuthenticatedUser());
        app.MapGet("/cookie-only", () => Results.Ok()).RequireAuthorization(policy => policy
            .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme)
            .RequireAuthenticatedUser());
    }

    private static async Task<HttpResponseMessage> CallAsync(OAuthTestHost host, string accessToken, string path)
    {
        using var api = host.Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await api.GetAsync(path);
    }

    private static Task Teapot(RedirectContext<CookieAuthenticationOptions> context, string name)
    {
        context.Response.StatusCode = 418;
        context.Response.Headers["X-Host-Event"] = name;
        return Task.CompletedTask;
    }

    private sealed class HostCookieEvents : CookieAuthenticationEvents
    {
        public override Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context) => Teapot(context, "events-type");

        public override Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context) => Teapot(context, "events-type");
    }
}
