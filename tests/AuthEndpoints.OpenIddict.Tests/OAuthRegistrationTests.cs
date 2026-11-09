using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using OpenIddict.Abstractions;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

public sealed class OAuthRegistrationTests
{
    [Fact]
    public async Task Dynamic_registration_rejects_confidential_clients_and_bad_redirects()
    {
        await using var host = await StartAsync();
        using var anon = host.Client(cookies: false);

        await AssertProtocolAsync(await Register(anon, new { redirect_uris = new[] { Loopback }, token_endpoint_auth_method = "client_secret_post" }), "invalid_client_metadata");
        await AssertProtocolAsync(await Register(anon, new { redirect_uris = new[] { Loopback }, token_endpoint_auth_method = "client_secret_basic" }), "invalid_client_metadata");
        await AssertProtocolAsync(await Register(anon, new { redirect_uris = new[] { Loopback }, client_secret = "shh" }), "invalid_client_metadata");
        await AssertProtocolAsync(await Register(anon, new { redirect_uris = new[] { Loopback }, grant_types = new[] { "client_credentials" } }), "invalid_client_metadata");
        await AssertProtocolAsync(await Register(anon, new { redirect_uris = new[] { Loopback }, response_types = new[] { "token" } }), "invalid_client_metadata");
        await AssertProtocolAsync(await Register(anon, new { redirect_uris = new[] { Loopback }, scope = "admin" }), "invalid_client_metadata");
        await AssertProtocolAsync(await Register(anon, new { redirect_uris = new[] { Loopback }, client_name = new string('x', 201) }), "invalid_client_metadata");
        await AssertProtocolAsync(await Register(anon, new { redirect_uris = new[] { "http://example.test/callback" } }), "invalid_redirect_uri");
        await AssertProtocolAsync(await Register(anon, new { redirect_uris = new[] { Loopback + "#frag" } }), "invalid_redirect_uri");
        await AssertProtocolAsync(await Register(anon, new { redirect_uris = new[] { "https://user:pw@example.test/cb" } }), "invalid_redirect_uri");
        await AssertProtocolAsync(await Register(anon, new { redirect_uris = Array.Empty<string>() }), "invalid_redirect_uri");

        var ok = await Register(anon, new { redirect_uris = new[] { "http://[::1]:8080/cb", "https://app.example/cb" } });
        Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
        var body = await ok.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("none", body.GetProperty("token_endpoint_auth_method").GetString());
        Assert.Equal("OAuth client", body.GetProperty("client_name").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("client_id").GetString()));
    }

    [Fact]
    public async Task Registration_is_off_by_default()
    {
        await using var host = await StartAsync(options => options.DynamicRegistration.Enabled = false);
        using var anon = host.Client(cookies: false);

        Assert.Equal(HttpStatusCode.NotFound, (await Register(anon, new { redirect_uris = new[] { Loopback } })).StatusCode);
        var metadata = await anon.GetStringAsync(".well-known/oauth-authorization-server");
        Assert.DoesNotContain("registration_endpoint", metadata, StringComparison.Ordinal);
        Assert.False(new OAuthServerOptions().DynamicRegistration.Enabled);
    }

    [Fact]
    public async Task Register_is_rate_limited_per_address()
    {
        await using var host = await StartAsync(options => options.DynamicRegistration.PermitsPerMinute = 2);
        using var anon = host.Client(cookies: false);
        using var other = host.Client(cookies: false);
        var body = new { redirect_uris = new[] { Loopback } };
        for (var i = 0; i < 2; i++)
        {
            Assert.Equal(HttpStatusCode.Created, (await Register(anon, body)).StatusCode);
        }

        var rejected = await Register(anon, body);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.Equal("application/problem+json", rejected.Content.Headers.ContentType?.MediaType);
        Assert.Equal(HttpStatusCode.Created, (await Register(other, body)).StatusCode);
    }

    [Fact]
    public async Task Unused_clients_are_deleted_and_approved_or_seeded_clients_stay()
    {
        var clock = new FakeTimeProvider(TimeProvider.System.GetUtcNow());
        await using var host = await StartAsync(
            options => options.DynamicRegistration.UnusedClientLifetime = TimeSpan.FromHours(1),
            services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(clock);
            });
        var (user, _) = await host.UserAsync("sweep");
        var (kept, _) = await host.IssueAsync(user, name: "Kept");
        var unused = await host.RegisterAsync("Unused");
        var pending = await host.RegisterAsync("Pending");
        var consent = await OAuthTestHost.StartAsync(user, pending.ClientId, pending.RedirectUri, Pkce.Create().Challenge);
        clock.Advance(TimeSpan.FromHours(2));

        var result = await host.Services.GetRequiredService<IOAuthServerCleanup>().SweepAsync();

        Assert.Equal(2, result.UnusedClients);
        // The pending request, plus the consumed one behind "Kept".
        Assert.Equal(2, result.ExpiredRequests);
        await using var scope = host.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync(unused.ClientId));
        Assert.Null(await applications.FindByClientIdAsync(pending.ClientId));
        Assert.NotNull(await applications.FindByClientIdAsync(kept.ClientId));
        Assert.NotNull(await applications.FindByClientIdAsync(SeededClientId));
        Assert.Equal(HttpStatusCode.NotFound, (await user.GetAsync($"/oauth/requests/{consent}")).StatusCode);
    }

    [Fact]
    public async Task Allowed_scopes_keep_first_party_scopes_from_registered_clients()
    {
        await using var host = await StartAsync(options =>
        {
            options.Scopes.Add("account");
            options.DefaultScopes.Add("account");
            options.DynamicRegistration.AllowedScopes.Add("api");
            var desktop = new OAuthClientDefinition { ClientId = "desktop", DisplayName = "Desktop" };
            desktop.RedirectUris.Add(Loopback);
            desktop.Scopes.Add("api");
            desktop.Scopes.Add("account");
            options.Clients.Add(desktop);
        });
        using var anon = host.Client(cookies: false);
        var (user, _) = await host.UserAsync("allowed");

        var rejected = await Register(anon, new { redirect_uris = new[] { Loopback }, scope = "api account" });
        await AssertProtocolAsync(rejected, "invalid_client_metadata");
        Assert.Contains("account", await rejected.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        // offline_access is always available.
        var client = await host.RegisterAsync("Third party", scope: "api offline_access");
        // OpenIddict's own scope permission check rejects it, as invalid_request.
        var asked = await user.GetAsync(AuthorizeUrl(client.ClientId, client.RedirectUri, Pkce.Create().Challenge, scope: "api account"));
        Assert.Contains(await AuthorizeErrorAsync(asked), new[] { "invalid_request", "invalid_scope" });

        // With no scope, default scopes the client may not hold are left out.
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge, scope: null);
        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, (await ApproveAsync(user, id))["code"], pkce.Verifier)));
        var me = await (await host.CallApiAsync(tokens.AccessToken)).Content.ReadFromJsonAsync<JsonElement>();
        var scopes = me.GetProperty("scopes").EnumerateArray().Select(item => item.GetString()).ToArray();
        Assert.Contains("api", scopes);
        Assert.DoesNotContain("account", scopes);

        // A configured first-party client still gets the scope.
        await OAuthTestHost.StartAsync(user, "desktop", Loopback, Pkce.Create().Challenge, scope: "api account");
    }

    [Fact]
    public async Task Allowed_scopes_also_hold_clients_registered_before_them()
    {
        await using var host = await StartAsync(options => options.Scopes.Add("account"));
        var (user, _) = await host.UserAsync("earlier");
        var client = await host.RegisterAsync("Earlier", scope: "api account");
        await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge, scope: "api account");

        host.Services.GetRequiredService<IOptions<OAuthServerOptions>>().Value.DynamicRegistration.AllowedScopes.Add("api");

        var asked = await user.GetAsync(AuthorizeUrl(client.ClientId, client.RedirectUri, Pkce.Create().Challenge, scope: "api account"));
        Assert.Equal("invalid_scope", await AuthorizeErrorAsync(asked));
        await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge, scope: "api");
    }

    private static Task<HttpResponseMessage> Register(HttpClient anon, object body)
        => anon.PostAsJsonAsync("/connect/register", body);

    private static async Task AssertProtocolAsync(HttpResponseMessage response, string error)
    {
        Assert.Equal(error, await ErrorAsync(response));
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }
}
