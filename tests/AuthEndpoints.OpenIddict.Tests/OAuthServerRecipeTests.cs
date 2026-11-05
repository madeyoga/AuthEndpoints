using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary><c>AddOAuthServer</c> / <c>MapOAuthServer</c>, the default recipe.</summary>
public sealed class OAuthServerRecipeTests
{
    private const string WebRedirect = "https://dev.example/callback";

    [Fact]
    public async Task Recipe_runs_the_whole_flow_through_a_developer_app_with_anonymous_registration_off()
    {
        // The shared test host turns dynamic registration on; put it back to the package default.
        await using var host = await StartAsync(options => options.DynamicRegistration.Enabled = false, recipe: true);
        using var anon = host.Client(cookies: false);

        var routes = Routes(host);
        Assert.Contains("/connect/authorize", routes);
        Assert.Contains("/oauth/requests/{id:guid}/approve", routes);
        Assert.Contains("/oauth/apps/{id:guid}/secret", routes);
        Assert.DoesNotContain("/connect/register", routes);

        var metadata = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-authorization-server");
        Assert.Equal(Issuer + "connect/token", metadata.GetProperty("token_endpoint").GetString());
        Assert.Equal(Issuer + "connect/revoke", metadata.GetProperty("revocation_endpoint").GetString());
        Assert.False(metadata.TryGetProperty("registration_endpoint", out _));
        var register = await anon.PostAsJsonAsync("/connect/register", new { redirect_uris = new[] { Loopback } });
        Assert.Equal(HttpStatusCode.NotFound, register.StatusCode);

        // The recipe registered antiforgery and authorization itself: the host only configured their options.
        var (owner, _) = await host.UserAsync("owner");
        var created = await PostJsonAsync(owner, "/oauth/apps", new { name = "Recipe app", homepageUrl = "https://dev.example", redirectUris = new[] { WebRedirect } });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var clientId = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("app").GetProperty("clientId").GetString()!;

        var (user, userId) = await host.UserAsync("user");
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, clientId, WebRedirect, pkce.Challenge);
        var card = await user.GetFromJsonAsync<JsonElement>($"/oauth/requests/{id}");
        Assert.Equal("Recipe app", card.GetProperty("clientName").GetString());
        Assert.False(card.GetProperty("confidential").GetBoolean());
        var approved = await ApproveAsync(user, id);

        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(clientId, WebRedirect, approved["code"], pkce.Verifier)));
        Assert.Equal(userId, await host.SubjectAsync(tokens.AccessToken));
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(clientId, tokens.RefreshToken)));
        Assert.Equal(userId, await host.SubjectAsync(refreshed.AccessToken));

        var revoke = await anon.PostAsync("/connect/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = refreshed.AccessToken,
            ["client_id"] = clientId,
        }));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.CallApiAsync(refreshed.AccessToken)).StatusCode);

        var revokeRefresh = await anon.PostAsync("/connect/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = refreshed.RefreshToken,
            ["token_type_hint"] = "refresh_token",
            ["client_id"] = clientId,
        }));
        Assert.Equal(HttpStatusCode.OK, revokeRefresh.StatusCode);
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(clientId, refreshed.RefreshToken))));
    }

    [Fact]
    public async Task Consent_api_and_developer_apps_can_be_turned_off_while_the_server_keeps_working()
    {
        await using var host = await StartAsync(
            recipe: true,
            endpoints: parts =>
            {
                parts.ConsentApi = false;
                parts.DeveloperApps = false;
            },
            map: app => app.MapPost("/host/approve/{id:guid}", async (Guid id, HttpContext http, IOAuthConsentService consent) =>
            {
                var result = await consent.ApproveAsync(id, http.User.FindFirstValue(ClaimTypes.NameIdentifier)!);
                return Results.Ok(new { redirectUrl = result.RedirectUrl });
            }).RequireAuthorization(new Microsoft.AspNetCore.Authorization.AuthorizeAttribute { AuthenticationSchemes = IdentityConstants.ApplicationScheme }));

        var routes = Routes(host);
        Assert.Contains("/connect/authorize", routes);
        Assert.Contains("/connect/register", routes); // the test host's options turn it on
        Assert.DoesNotContain(routes, route => route.StartsWith("/oauth/", StringComparison.Ordinal));

        var (user, userId) = await host.UserAsync("user");
        Assert.Equal(HttpStatusCode.NotFound, (await user.GetAsync("/oauth/apps")).StatusCode);

        // The host approves through IOAuthConsentService from its own route.
        var client = await host.RegisterAsync("Own consent page");
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge);
        Assert.Equal(HttpStatusCode.NotFound, (await user.GetAsync($"/oauth/requests/{id}")).StatusCode);
        var approve = await user.PostAsync($"/host/approve/{id}", null);
        var redirect = (await approve.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("redirectUrl").GetString()!;
        using var anon = host.Client(cookies: false);
        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, Query(redirect)["code"], pkce.Verifier)));
        Assert.Equal(userId, await host.SubjectAsync(tokens.AccessToken));
    }

    [Fact]
    public async Task Enabled_dynamic_registration_is_mapped_and_parts_can_move()
    {
        await using var host = await StartAsync(
            recipe: true,
            endpoints: parts =>
            {
                parts.ConsentPrefix = "/account/oauth";
                parts.DeveloperAppsPrefix = "/developers/apps";
            },
            server: oauth => oauth.AddPrincipalFactory<PrefixedSubjectFactory>());
        using var anon = host.Client(cookies: false);

        var metadata = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-authorization-server");
        Assert.Equal(Issuer + "connect/register", metadata.GetProperty("registration_endpoint").GetString());
        var routes = Routes(host);
        Assert.Contains("/account/oauth/requests/{id:guid}", routes);
        Assert.Contains("/developers/apps/", routes);
        Assert.DoesNotContain(routes, route => route.StartsWith("/oauth/", StringComparison.Ordinal));

        var (user, userId) = await host.UserAsync("user");
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/developers/apps")).StatusCode);
        var client = await host.RegisterAsync("Moved");
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge);
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync($"/account/oauth/requests/{id}")).StatusCode);
        var approve = await PostJsonAsync(user, $"/account/oauth/requests/{id}/approve", body: null);
        var redirect = (await approve.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("redirectUrl").GetString()!;
        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, Query(redirect)["code"], pkce.Verifier)));

        // AddOAuthServer returns the same builder, so AddPrincipalFactory still applies.
        Assert.Equal("agent:" + userId, await host.SubjectAsync(tokens.AccessToken));
    }

    [Fact]
    public void Map_returns_the_groups_it_mapped()
    {
        var app = Build<TestDb>(services => services.AddOAuthServer<IdentityUser, TestDb>(Valid));
        var all = app.MapOAuthServer();
        Assert.NotNull(all.Consent);
        Assert.NotNull(all.DeveloperApps);

        var other = Build<TestDb>(services => services.AddOAuthServer<IdentityUser, TestDb>(Valid));
        var none = other.MapOAuthServer(parts =>
        {
            parts.ConsentApi = false;
            parts.DeveloperApps = false;
        });
        Assert.Null(none.Consent);
        Assert.Null(none.DeveloperApps);
    }

    [Fact]
    public void Registering_twice_fails()
    {
        var twice = Assert.Throws<InvalidOperationException>(() => Build<TestDb>(services =>
        {
            services.AddOAuthServer<IdentityUser, TestDb>(Valid);
            services.AddOAuthServer<IdentityUser, TestDb>(Valid);
        }));
        Assert.Contains("already registered", twice.Message, StringComparison.Ordinal);

        Assert.Throws<InvalidOperationException>(() => Build<TestDb>(services =>
        {
            services.AddAuthEndpointsOpenIddict<IdentityUser, TestDb>(Valid);
            services.AddOAuthServer<IdentityUser, TestDb>(Valid);
        }));
    }

    [Fact]
    public void Map_fails_without_registration()
    {
        var app = Build<TestDb>(_ => { });
        var error = Assert.Throws<InvalidOperationException>(() => app.MapOAuthServer());
        Assert.Contains("AddOAuthServer", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Map_fails_when_the_model_lacks_the_oauth_tables()
    {
        var app = Build<PlainDb>(services => services.AddOAuthServer<IdentityUser, PlainDb>(Valid));
        var error = Assert.Throws<InvalidOperationException>(() => app.MapOAuthServer());
        Assert.Contains("UseAuthEndpointsOpenIddict<TUser>()", error.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(PlainDb), error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Map_fails_on_invalid_settings_before_any_request()
    {
        var app = Build<TestDb>(services => services.AddOAuthServer<IdentityUser, TestDb>(options =>
        {
            Valid(options);
            options.ConsentUrl = null;
        }));
        var error = Assert.Throws<Microsoft.Extensions.Options.OptionsValidationException>(() => app.MapOAuthServer());
        Assert.Contains("ConsentUrl", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("oauth")]
    [InlineData("//evil.example")]
    public void Map_rejects_a_prefix_that_is_not_rooted(string prefix)
    {
        var app = Build<TestDb>(services => services.AddOAuthServer<IdentityUser, TestDb>(Valid));
        Assert.Throws<ArgumentException>(() => app.MapOAuthServer(parts => parts.DeveloperAppsPrefix = prefix));
        Assert.Throws<ArgumentException>(() => app.MapOAuthServer(parts => parts.ConsentPrefix = prefix));

        // A part that is off is not checked.
        var off = app.MapOAuthServer(parts =>
        {
            parts.ConsentApi = false;
            parts.DeveloperApps = false;
            parts.ConsentPrefix = prefix;
            parts.DeveloperAppsPrefix = prefix;
        });
        Assert.Null(off.Consent);
    }

    [Fact]
    public void Endpoint_option_defaults_turn_every_part_on()
    {
        var parts = new OAuthServerEndpointOptions();
        Assert.True(parts.ConsentApi);
        Assert.True(parts.DeveloperApps);
        Assert.Equal("/oauth", parts.ConsentPrefix);
        Assert.Equal("/oauth/apps", parts.DeveloperAppsPrefix);
        Assert.False(new OAuthServerOptions().DynamicRegistration.Enabled);
    }

    private static void Valid(OAuthServerOptions options)
    {
        options.Issuer = new Uri(Issuer);
        options.Audience = Audience;
        options.Scopes.Add("api");
        options.LoginUrl = LoginUrl;
        options.ConsentUrl = ConsentUrl;
        options.Certificates.UseEphemeralKeys = true;
        options.CleanupInterval = TimeSpan.Zero;
    }

    /// <summary>A built, never started app. Model building needs a provider but no database.</summary>
    private static WebApplication Build<TContext>(Action<IServiceCollection> services)
        where TContext : DbContext
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TContext>(options => options.UseSqlite("Data Source=:memory:"));
        builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<TContext>();
        services(builder.Services);
        return builder.Build();
    }

    private static string[] Routes(OAuthTestHost host)
        => host.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Select(endpoint => endpoint.RoutePattern.RawText!)
            .ToArray();

    private static async Task<HttpResponseMessage> PostJsonAsync(HttpClient client, string path, object? body)
    {
        var csrf = await client.GetFromJsonAsync<JsonElement>("/test/csrf");
        using var request = new HttpRequestMessage(HttpMethod.Post, path);
        request.Headers.Add(CsrfHeader, csrf.GetProperty("token").GetString());
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return await client.SendAsync(request);
    }

    private sealed class PlainDb(DbContextOptions<PlainDb> options) : IdentityDbContext<IdentityUser>(options);

    private sealed class PrefixedSubjectFactory : IOAuthPrincipalFactory
    {
        public ValueTask<ClaimsPrincipal?> CreateAsync(OAuthPrincipalContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult<ClaimsPrincipal?>(OAuthPrincipals.ForSubject("agent:" + context.UserId));
    }
}
