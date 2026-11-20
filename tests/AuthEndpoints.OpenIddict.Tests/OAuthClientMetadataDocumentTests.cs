using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using OpenIddict.Abstractions;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>
/// Client ID metadata documents. Every fetch goes to <see cref="FakeDocumentServer"/> and every host name to
/// <see cref="FakeDns"/>: these tests never touch the network.
/// </summary>
public sealed class OAuthClientMetadataDocumentTests
{
    private const string ClientUrl = "https://client.example/oauth/client.json";
    private const string PublicV4 = "93.184.215.14";

    [Fact]
    public async Task A_metadata_document_client_completes_the_code_flow_and_the_card_shows_its_host()
    {
        var server = new FakeDocumentServer();
        server.Serve(ClientUrl, Document(ClientUrl, name: "Example Assistant"));
        await using var host = await HostAsync(server);
        var (user, _) = await host.UserAsync("cimd");
        var pkce = Pkce.Create();

        var id = await StartAsync(user, ClientUrl, Loopback, pkce.Challenge);
        var card = await user.GetFromJsonAsync<JsonElement>($"/oauth/requests/{id}");
        Assert.Equal(ClientUrl, card.GetProperty("clientId").GetString());
        Assert.Equal("Example Assistant", card.GetProperty("clientName").GetString());
        Assert.Equal("client.example", card.GetProperty("clientHost").GetString());

        var approved = await ApproveAsync(user, id);
        using var anon = host.Client(cookies: false);
        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(ClientUrl, Loopback, approved["code"], pkce.Verifier)));
        Assert.False(string.IsNullOrEmpty(await host.SubjectAsync(tokens.AccessToken)));
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(ClientUrl, tokens.RefreshToken)));
        Assert.False(string.IsNullOrEmpty(refreshed.AccessToken));

        // One fetch, with Accept: application/json and nothing that identifies the user.
        var request = Assert.Single(server.Requests);
        Assert.Equal(ClientUrl, request.Url);
        Assert.Contains("application/json", request.Accept, StringComparison.Ordinal);
        Assert.False(request.HadCookie);
        Assert.False(request.HadAuthorization);

        // Stored in OpenIddict's application store, as a public client.
        await using var scope = host.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(ClientUrl);
        Assert.NotNull(application);
        Assert.Equal(OpenIddictConstants.ClientTypes.Public, await applications.GetClientTypeAsync(application));
    }

    [Fact]
    public async Task Metadata_advertises_support_only_when_enabled()
    {
        await using (var host = await HostAsync(new FakeDocumentServer()))
        {
            using var anon = host.Client(cookies: false);
            var metadata = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-authorization-server");
            Assert.True(metadata.GetProperty("client_id_metadata_document_supported").GetBoolean());
            Assert.True(metadata.TryGetProperty("registration_endpoint", out _));
        }

        var server = new FakeDocumentServer();
        server.Serve(ClientUrl, Document(ClientUrl));
        await using (var off = await HostAsync(server, options => options.ClientMetadataDocuments.Enabled = false))
        {
            using var anon = off.Client(cookies: false);
            var metadata = await anon.GetStringAsync(".well-known/oauth-authorization-server");
            Assert.DoesNotContain("client_id_metadata_document_supported", metadata, StringComparison.Ordinal);
            var (user, _) = await off.UserAsync("off");
            // An unknown client, as any other.
            Assert.Contains(await RefusedAsync(user, ClientUrl), new[] { "invalid_client", "invalid_request" });
            Assert.Empty(server.Requests);
        }

        Assert.False(new OAuthServerOptions().ClientMetadataDocuments.Enabled);
    }

    [Fact]
    public async Task Dynamic_registration_keeps_working_alongside()
    {
        await using var host = await HostAsync(new FakeDocumentServer());
        var (user, _) = await host.UserAsync("both");
        var (_, tokens) = await host.IssueAsync(user);
        Assert.False(string.IsNullOrEmpty(await host.SubjectAsync(tokens.AccessToken)));
    }

    [Theory]
    [InlineData("http://client.example/oauth/client.json")]
    [InlineData("https://client.example")]
    [InlineData("https://client.example/")]
    [InlineData("https://client.example/oauth/client.json?v=1")]
    [InlineData("https://client.example/oauth/client.json#frag")]
    [InlineData("https://user:pw@client.example/oauth/client.json")]
    [InlineData("https://client.example/oauth/../client.json")]
    [InlineData("https://client.example/./client.json")]
    [InlineData("https://client.example/%2e%2e/client.json")]
    [InlineData("https://10.0.0.5/client.json")]
    [InlineData("https://127.0.0.1/client.json")]
    [InlineData("https://169.254.169.254/latest/meta-data")]
    [InlineData("https://[::1]/client.json")]
    [InlineData("https://[fd00::1]/client.json")]
    [InlineData("https://[::ffff:192.168.1.1]/client.json")]
    [InlineData("https://private.example/client.json")]
    [InlineData("https://loopback.example/client.json")]
    [InlineData("https://mixed.example/client.json")]
    public async Task Bad_urls_and_private_addresses_are_refused_without_a_request(string clientId)
    {
        var server = new FakeDocumentServer();
        server.Serve(clientId, Document(clientId));
        await using var host = await HostAsync(server);
        var (user, _) = await host.UserAsync("ssrf");

        // http://… is not a metadata document URL at all: OpenIddict refuses it as it refuses any unknown client id.
        Assert.Contains(await RefusedAsync(user, clientId), new[] { "invalid_client", "invalid_request" });
        Assert.Empty(server.Requests);
    }

    [Fact]
    public async Task Unreachable_large_redirected_and_malformed_documents_are_refused()
    {
        var server = new FakeDocumentServer();
        var cases = new Dictionary<string, Func<string, HttpResponseMessage>>
        {
            ["unreachable"] = _ => throw new HttpRequestException("connection refused"),
            ["missing"] = _ => new HttpResponseMessage(HttpStatusCode.NotFound),
            ["error"] = _ => new HttpResponseMessage(HttpStatusCode.InternalServerError),
            ["redirect"] = _ => new HttpResponseMessage(HttpStatusCode.Found) { Headers = { Location = new Uri("https://client.example/other.json") } },
            ["large"] = url => Json(Document(url, name: new string('x', 6000))),
            ["not-json"] = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html></html>", Encoding.UTF8, "text/html") },
            ["array"] = _ => Json("[]"),
            ["mismatch"] = _ => Json(Document("https://client.example/someone-else.json")),
            ["trailing-slash"] = url => Json(Document(url + "/")),
            ["bad-redirect"] = url => Json(Document(url, redirect: "http://client.example/callback")),
            ["fragment-redirect"] = url => Json(Document(url, redirect: "https://client.example/cb#x")),
            ["no-redirects"] = url => Json(Document(url, redirect: null)),
            ["secret"] = url => Json(Document(url, extra: new() { ["client_secret"] = "s3cret" })),
            ["basic"] = url => Json(Document(url, extra: new() { ["token_endpoint_auth_method"] = "client_secret_basic" })),
            ["post-supported"] = url => Json(Document(url, extra: new() { ["token_endpoint_auth_methods_supported"] = new[] { "none", "client_secret_post" } })),
            ["jwt-only"] = url => Json(Document(url, extra: new() { ["token_endpoint_auth_method"] = "private_key_jwt", ["jwks_uri"] = "https://client.example/jwks" })),
            ["both-keys"] = url => Json(Document(url, extra: new() { ["jwks"] = new { keys = Array.Empty<object>() }, ["jwks_uri"] = "https://client.example/jwks" })),
            ["no-code-grant"] = url => Json(Document(url, extra: new() { ["grant_types"] = new[] { "client_credentials" } })),
            ["no-code-response"] = url => Json(Document(url, extra: new() { ["response_types"] = new[] { "token" } })),
            ["long-name"] = url => Json(Document(url, name: new string('n', 201))),
        };
        foreach (var (name, respond) in cases)
        {
            var url = $"https://client.example/{name}.json";
            server.Serve(url, request => respond(url));
        }

        await using var host = await HostAsync(server);
        var (user, _) = await host.UserAsync("bad");
        foreach (var name in cases.Keys)
        {
            var url = $"https://client.example/{name}.json";
            Assert.True("invalid_client" == await RefusedAsync(user, url), name);
            await using var scope = host.Services.CreateAsyncScope();
            Assert.True(
                await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().FindByClientIdAsync(url) is null,
                $"{name} was stored");
        }

        // Exactly one request per case: the redirect was not followed.
        Assert.Equal(cases.Count, server.Requests.Count);
        Assert.DoesNotContain(server.Requests, request => request.Url.EndsWith("/other.json", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Accepted_variants_of_the_document()
    {
        var server = new FakeDocumentServer();
        var cases = new Dictionary<string, Func<string, string>>
        {
            // No authentication method at all means none, not RFC 7591's client_secret_basic.
            ["plain"] = url => Document(url),
            ["none-in-list"] = url => Document(url, extra: new() { ["token_endpoint_auth_methods_supported"] = new[] { "private_key_jwt", "none" }, ["jwks_uri"] = "https://client.example/jwks" }),
            ["extra-grants"] = url => Document(url, extra: new() { ["grant_types"] = new[] { "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code" } }),
            ["unknown-scope"] = url => Document(url, extra: new() { ["scope"] = "something.this.server.does.not.have", ["logo_uri"] = "https://client.example/logo.png" }),
            ["no-name"] = url => Document(url, name: null),
        };
        foreach (var (name, document) in cases)
        {
            var url = $"https://client.example/{name}.json";
            server.Serve(url, document(url));
        }

        await using var host = await HostAsync(server);
        var (user, _) = await host.UserAsync("ok");
        foreach (var name in cases.Keys)
        {
            var url = $"https://client.example/{name}.json";
            var id = await StartAsync(user, url, Loopback, Pkce.Create().Challenge);
            var card = await user.GetFromJsonAsync<JsonElement>($"/oauth/requests/{id}");
            Assert.Equal(name == "no-name" ? "client.example" : "Metadata Client", card.GetProperty("clientName").GetString());
        }
    }

    [Fact]
    public async Task Without_refresh_token_in_grant_types_no_refresh_token_is_issued()
    {
        var server = new FakeDocumentServer();
        server.Serve(ClientUrl, Document(ClientUrl, extra: new() { ["grant_types"] = new[] { "authorization_code" } }));
        await using var host = await HostAsync(server);
        var (user, _) = await host.UserAsync("norefresh");
        var pkce = Pkce.Create();
        var approved = await ApproveAsync(user, await StartAsync(user, ClientUrl, Loopback, pkce.Challenge));
        using var anon = host.Client(cookies: false);
        var response = await TokenAsync(anon, CodeGrant(ClientUrl, Loopback, approved["code"], pkce.Verifier));
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(body.TryGetProperty("refresh_token", out _));
    }

    [Fact]
    public async Task A_redirect_uri_not_in_the_document_is_refused()
    {
        var server = new FakeDocumentServer();
        server.Serve(ClientUrl, Document(ClientUrl, redirect: "https://client.example/callback"));
        await using var host = await HostAsync(server);
        var (user, _) = await host.UserAsync("redirect");
        var response = await user.GetAsync(AuthorizeUrl(ClientUrl, "https://evil.example/callback", Pkce.Create().Challenge));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Loopback_redirects_may_use_any_port()
    {
        var server = new FakeDocumentServer();
        server.Serve(ClientUrl, Document(ClientUrl, redirect: "http://127.0.0.1/callback"));
        await using var host = await HostAsync(server);
        var (user, _) = await host.UserAsync("ports");
        await StartAsync(user, ClientUrl, "http://127.0.0.1:51234/callback", Pkce.Create().Challenge);
    }

    [Fact]
    public async Task Documents_are_cached_within_bounds_and_fetched_again_when_stale()
    {
        var clock = new FakeTimeProvider(TimeProvider.System.GetUtcNow());
        var server = new FakeDocumentServer();
        var name = "First name";
        server.Serve(ClientUrl, _ =>
        {
            var response = Json(Document(ClientUrl, name: name));
            response.Headers.CacheControl = new CacheControlHeaderValue { MaxAge = TimeSpan.FromHours(1) };
            return response;
        });
        await using var host = await HostAsync(server, clock: clock);
        var (user, _) = await host.UserAsync("cache");

        Assert.Equal("First name", await CardNameAsync(user));
        name = "Second name";
        clock.Advance(TimeSpan.FromMinutes(59));
        Assert.Equal("First name", await CardNameAsync(user));
        Assert.Single(server.Requests);

        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal("Second name", await CardNameAsync(user));
        Assert.Equal(2, server.Requests.Count);

        // The client was updated in place, not created twice.
        await using var scope = host.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Equal("Second name", await applications.GetDisplayNameAsync((await applications.FindByClientIdAsync(ClientUrl))!));
    }

    [Theory]
    [InlineData("no-store", 5)]
    [InlineData("max-age=1", 5)]
    [InlineData(null, 5)]
    [InlineData("max-age=31536000", 24 * 60)]
    public async Task Cache_lifetime_is_clamped(string? cacheControl, int expectedMinutes)
    {
        var clock = new FakeTimeProvider(TimeProvider.System.GetUtcNow());
        var server = new FakeDocumentServer();
        server.Serve(ClientUrl, _ =>
        {
            var response = Json(Document(ClientUrl));
            if (cacheControl is not null)
            {
                response.Headers.TryAddWithoutValidation("Cache-Control", cacheControl);
            }

            return response;
        });
        await using var host = await HostAsync(server, clock: clock);
        var (user, _) = await host.UserAsync("clamp");

        await StartAsync(user, ClientUrl, Loopback, Pkce.Create().Challenge);
        clock.Advance(TimeSpan.FromMinutes(expectedMinutes) - TimeSpan.FromSeconds(1));
        await StartAsync(user, ClientUrl, Loopback, Pkce.Create().Challenge);
        Assert.Single(server.Requests);
        clock.Advance(TimeSpan.FromSeconds(2));
        await StartAsync(user, ClientUrl, Loopback, Pkce.Create().Challenge);
        Assert.Equal(2, server.Requests.Count);
    }

    [Fact]
    public async Task A_network_failure_keeps_the_stored_client_and_a_bad_document_does_not()
    {
        var clock = new FakeTimeProvider(TimeProvider.System.GetUtcNow());
        var server = new FakeDocumentServer();
        Func<HttpResponseMessage> respond = () => Json(Document(ClientUrl));
        server.Serve(ClientUrl, _ => respond());
        await using var host = await HostAsync(server, clock: clock);
        var (user, _) = await host.UserAsync("stale");
        await StartAsync(user, ClientUrl, Loopback, Pkce.Create().Challenge);

        // Transient: the stored copy is used, and fetched again on the next request.
        respond = () => throw new HttpRequestException("down");
        clock.Advance(TimeSpan.FromMinutes(6));
        await StartAsync(user, ClientUrl, Loopback, Pkce.Create().Challenge);
        respond = () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        await StartAsync(user, ClientUrl, Loopback, Pkce.Create().Challenge);
        Assert.Equal(3, server.Requests.Count);

        // Terminal: the client now claims another id. Refused, and still refused on the next try.
        respond = () => Json(Document("https://client.example/other.json"));
        Assert.Equal("invalid_client", await RefusedAsync(user, ClientUrl));
        Assert.Equal("invalid_client", await RefusedAsync(user, ClientUrl));
    }

    [Fact]
    public async Task Hosts_are_filtered_by_the_lists_and_the_hook()
    {
        var server = new FakeDocumentServer();
        foreach (var url in new[] { "https://denied.example/c.json", "https://app.trusted.example/c.json", "https://other.example/c.json", "https://hooked.trusted.example/c.json" })
        {
            server.Serve(url, Document(url));
        }

        await using var host = await HostAsync(
            server,
            options =>
            {
                options.ClientMetadataDocuments.AllowedHosts.Add("*.trusted.example");
                options.ClientMetadataDocuments.AllowedHosts.Add("denied.example");
                options.ClientMetadataDocuments.DeniedHosts.Add("DENIED.example");
            },
            oauth: builder => builder.AddClientMetadataHostFilter<NotHookedFilter>());
        var (user, _) = await host.UserAsync("hosts");

        Assert.Equal("invalid_client", await RefusedAsync(user, "https://denied.example/c.json"));
        Assert.Equal("invalid_client", await RefusedAsync(user, "https://other.example/c.json"));
        Assert.Equal("invalid_client", await RefusedAsync(user, "https://hooked.trusted.example/c.json"));
        Assert.Empty(server.Requests);
        await StartAsync(user, "https://app.trusted.example/c.json", Loopback, Pkce.Create().Challenge);
        Assert.Single(server.Requests);
    }

    [Fact]
    public async Task Scopes_are_limited_to_the_dynamic_registration_allow_list()
    {
        var server = new FakeDocumentServer();
        server.Serve(ClientUrl, Document(ClientUrl));
        await using var host = await HostAsync(server, options => options.DynamicRegistration.AllowedScopes.Add("api"));
        var (user, _) = await host.UserAsync("scopes");

        await StartAsync(user, ClientUrl, Loopback, Pkce.Create().Challenge, scope: "api");
        // OpenIddict's own scope permission check rejects it, as invalid_request.
        var response = await user.GetAsync(AuthorizeUrl(ClientUrl, Loopback, Pkce.Create().Challenge, scope: "api profile"));
        Assert.Contains(await AuthorizeErrorAsync(response), new[] { "invalid_request", "invalid_scope" });
    }

    [Fact]
    public async Task Fetches_are_rate_limited_per_caller()
    {
        var server = new FakeDocumentServer();
        server.Serve("https://client.example/a.json", Document("https://client.example/a.json"));
        server.Serve("https://client.example/b.json", Document("https://client.example/b.json"));
        await using var host = await HostAsync(server, options => options.ClientMetadataDocuments.FetchesPerMinute = 1);
        var (user, _) = await host.UserAsync("limit");
        var (other, _) = await host.UserAsync("limit2");

        await StartAsync(user, "https://client.example/a.json", Loopback, Pkce.Create().Challenge);
        // A stored client does not need a fetch, so it is not limited.
        await StartAsync(user, "https://client.example/a.json", Loopback, Pkce.Create().Challenge);
        Assert.Equal("invalid_client", await RefusedAsync(user, "https://client.example/b.json"));
        await StartAsync(other, "https://client.example/b.json", Loopback, Pkce.Create().Challenge);
        Assert.Equal(2, server.Requests.Count);
    }

    [Fact]
    public async Task A_configured_client_with_a_url_id_is_never_fetched_or_replaced()
    {
        const string configured = "https://configured.example/client";
        var server = new FakeDocumentServer();
        server.Serve(configured, Document(configured, name: "Impostor", redirect: "https://evil.example/cb"));
        await using var host = await HostAsync(server, options =>
        {
            var client = new OAuthClientDefinition { ClientId = configured, DisplayName = "Configured" };
            client.RedirectUris.Add(Loopback);
            options.Clients.Add(client);
        });
        var (user, _) = await host.UserAsync("configured");

        var id = await StartAsync(user, configured, Loopback, Pkce.Create().Challenge);
        var card = await user.GetFromJsonAsync<JsonElement>($"/oauth/requests/{id}");
        Assert.Equal("Configured", card.GetProperty("clientName").GetString());
        Assert.Equal(JsonValueKind.Null, card.GetProperty("clientHost").ValueKind);
        Assert.Empty(server.Requests);
    }

    [Fact]
    public async Task Turning_the_feature_off_stops_stored_clients_at_authorize()
    {
        var server = new FakeDocumentServer();
        server.Serve(ClientUrl, Document(ClientUrl));
        await using var host = await HostAsync(server);
        var (user, _) = await host.UserAsync("toggle");
        await StartAsync(user, ClientUrl, Loopback, Pkce.Create().Challenge);

        host.Services.GetRequiredService<IOptions<OAuthServerOptions>>().Value.ClientMetadataDocuments.Enabled = false;
        Assert.Equal("invalid_client", await RefusedAsync(user, ClientUrl));
    }

    [Fact]
    public async Task Unused_metadata_clients_are_cleaned_up_and_approved_ones_stay()
    {
        var clock = new FakeTimeProvider(TimeProvider.System.GetUtcNow());
        var server = new FakeDocumentServer();
        server.Serve("https://client.example/unused.json", Document("https://client.example/unused.json"));
        server.Serve("https://client.example/used.json", Document("https://client.example/used.json"));
        await using var host = await HostAsync(server, options => options.DynamicRegistration.UnusedClientLifetime = TimeSpan.FromHours(1), clock: clock);
        var (user, _) = await host.UserAsync("cleanup");
        await StartAsync(user, "https://client.example/unused.json", Loopback, Pkce.Create().Challenge);
        await ApproveAsync(user, await StartAsync(user, "https://client.example/used.json", Loopback, Pkce.Create().Challenge));

        clock.Advance(TimeSpan.FromHours(2));
        var result = await host.Services.GetRequiredService<IOAuthServerCleanup>().SweepAsync();
        Assert.Equal(1, result.UnusedClients);
        await using var scope = host.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync("https://client.example/unused.json"));
        Assert.NotNull(await applications.FindByClientIdAsync("https://client.example/used.json"));

        // A deleted client is simply fetched again.
        await StartAsync(user, "https://client.example/unused.json", Loopback, Pkce.Create().Challenge);
    }

    [Theory]
    [InlineData("93.184.215.14", true)]
    [InlineData("8.8.8.8", true)]
    [InlineData("2606:2800:21f:cb07:6820:80da:af6b:8b2c", true)]
    [InlineData("0.0.0.0", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.31.255.255", false)]
    [InlineData("192.0.0.8", false)]
    [InlineData("192.0.2.1", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("198.18.0.1", false)]
    [InlineData("198.51.100.1", false)]
    [InlineData("203.0.113.1", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("::", false)]
    [InlineData("::1", false)]
    [InlineData("::ffff:127.0.0.1", false)]
    [InlineData("::ffff:93.184.215.14", true)]
    [InlineData("fe80::1", false)]
    [InlineData("fc00::1", false)]
    [InlineData("fd12:3456::1", false)]
    [InlineData("ff02::1", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("2001::1", false)]
    [InlineData("64:ff9b::a00:1", false)]
    [InlineData("2002:0a00:0001::1", false)]
    [InlineData("2002:5db8:d70e::1", true)]
    public void Only_public_addresses_are_fetched(string address, bool expected)
        => Assert.Equal(expected, OAuthClientMetadataAddresses.IsPublic(IPAddress.Parse(address)));

    [Theory]
    [InlineData("example.com", "example.com", true)]
    [InlineData("example.com", "EXAMPLE.com", true)]
    [InlineData("example.com", "a.example.com", false)]
    [InlineData("*.example.com", "a.example.com", true)]
    [InlineData("*.example.com", "a.b.example.com", true)]
    [InlineData("*.example.com", "example.com", false)]
    [InlineData("*.example.com", "badexample.com", false)]
    public void Host_patterns_match(string pattern, string host, bool expected)
        => Assert.Equal(expected, OAuthClientMetadataHosts.Matches(pattern, host));

    [Fact]
    public void Options_are_validated_when_enabled()
    {
        var options = Valid();
        options.ClientMetadataDocuments.Enabled = true;
        options.ClientMetadataDocuments.MinCacheDuration = TimeSpan.FromHours(2);
        options.ClientMetadataDocuments.MaxCacheDuration = TimeSpan.FromHours(1);
        options.ClientMetadataDocuments.MaxDocumentBytes = 10;
        options.ClientMetadataDocuments.FetchesPerMinute = 0;
        options.ClientMetadataDocuments.FetchTimeout = TimeSpan.Zero;
        options.ClientMetadataDocuments.AllowedHosts.Add("https://example.com");
        options.ClientMetadataDocuments.DeniedHosts.Add("*");
        var failures = new OAuthServerOptionsValidator().Validate(null, options).Failures!.ToList();
        Assert.Contains(failures, failure => failure.Contains("MaxCacheDuration", StringComparison.Ordinal));
        Assert.Contains(failures, failure => failure.Contains("MaxDocumentBytes", StringComparison.Ordinal));
        Assert.Contains(failures, failure => failure.Contains("FetchesPerMinute", StringComparison.Ordinal));
        Assert.Contains(failures, failure => failure.Contains("FetchTimeout", StringComparison.Ordinal));
        Assert.Contains(failures, failure => failure.Contains("'https://example.com'", StringComparison.Ordinal));
        Assert.Contains(failures, failure => failure.Contains("'*'", StringComparison.Ordinal));
    }

    private static OAuthServerOptions Valid()
    {
        var options = new OAuthServerOptions
        {
            Issuer = new Uri(Issuer),
            Audience = Audience,
            LoginUrl = LoginUrl,
            ConsentUrl = ConsentUrl,
        };
        options.Certificates.UseEphemeralKeys = true;
        return options;
    }

    private static async Task<string?> CardNameAsync(HttpClient user)
    {
        var id = await StartAsync(user, ClientUrl, Loopback, Pkce.Create().Challenge);
        return (await user.GetFromJsonAsync<JsonElement>($"/oauth/requests/{id}")).GetProperty("clientName").GetString();
    }

    /// <summary>
    /// The error of a refused authorize request. A client that failed its document check is never trusted with a redirect,
    /// so the error is always rendered by this server.
    /// </summary>
    private static async Task<string> RefusedAsync(HttpClient user, string clientId)
    {
        var response = await user.GetAsync(AuthorizeUrl(clientId, Loopback, Pkce.Create().Challenge));
        Assert.True(
            response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized,
            $"{(int)response.StatusCode} {response.Headers.Location}");
        var text = await response.Content.ReadAsStringAsync();
        var line = text.Split('\n').First(item => item.StartsWith("error:", StringComparison.Ordinal));
        return line["error:".Length..].Trim();
    }

    private static Task<OAuthTestHost> HostAsync(
        FakeDocumentServer server,
        Action<OAuthServerOptions>? configure = null,
        Action<OAuthServerBuilder>? oauth = null,
        FakeTimeProvider? clock = null)
        => OAuthTestHost.StartAsync(
            options =>
            {
                options.ClientMetadataDocuments.Enabled = true;
                configure?.Invoke(options);
            },
            services =>
            {
                services.AddHttpClient(OAuthClientMetadataFetcher.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => server);
                services.RemoveAll<IOAuthClientMetadataDnsResolver>();
                services.AddSingleton<IOAuthClientMetadataDnsResolver>(new FakeDns());
                if (clock is not null)
                {
                    services.RemoveAll<TimeProvider>();
                    services.AddSingleton<TimeProvider>(clock);
                }
            },
            server: oauth);

    private static string Document(string clientId, string? name = "Metadata Client", string? redirect = Loopback, Dictionary<string, object>? extra = null)
    {
        var document = new Dictionary<string, object> { ["client_id"] = clientId };
        if (name is not null)
        {
            document["client_name"] = name;
        }

        if (redirect is not null)
        {
            document["redirect_uris"] = new[] { redirect };
        }

        foreach (var (key, value) in extra ?? [])
        {
            document[key] = value;
        }

        return JsonSerializer.Serialize(document);
    }

    private static HttpResponseMessage Json(string body)
        => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class NotHookedFilter : IOAuthClientMetadataHostFilter
    {
        public ValueTask<bool> IsAllowedAsync(Uri clientId, CancellationToken cancellationToken)
            => ValueTask.FromResult(!clientId.Host.StartsWith("hooked.", StringComparison.Ordinal));
    }

    /// <summary>Public addresses for every name, except the ones meant to resolve somewhere private.</summary>
    private sealed class FakeDns : IOAuthClientMetadataDnsResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(host switch
        {
            "private.example" => new[] { IPAddress.Parse("10.0.0.7") },
            "loopback.example" => [IPAddress.Parse("::1")],
            "mixed.example" => [IPAddress.Parse(PublicV4), IPAddress.Parse("192.168.0.10")],
            _ => [IPAddress.Parse(PublicV4)],
        });
    }

    internal sealed record SeenRequest(string Url, string Accept, bool HadCookie, bool HadAuthorization);

    /// <summary>Stands in for the network. Unknown URLs get 404.</summary>
    internal sealed class FakeDocumentServer : HttpMessageHandler
    {
        private readonly ConcurrentDictionary<string, Func<HttpRequestMessage, HttpResponseMessage>> routes = new(StringComparer.Ordinal);

        public ConcurrentQueue<SeenRequest> Requests { get; } = new();

        public void Serve(string url, string document) => Serve(url, _ => Json(document));

        public void Serve(string url, Func<HttpRequestMessage, HttpResponseMessage> respond) => routes[url] = respond;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.OriginalString;
            Requests.Enqueue(new SeenRequest(
                url,
                request.Headers.Accept.ToString(),
                request.Headers.Contains("Cookie"),
                request.Headers.Authorization is not null));
            return Task.FromResult(routes.TryGetValue(url, out var respond) ? respond(request) : new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        // The client factory disposes handlers it rotates; this one is shared by the whole test.
        protected override void Dispose(bool disposing)
        {
        }
    }
}
