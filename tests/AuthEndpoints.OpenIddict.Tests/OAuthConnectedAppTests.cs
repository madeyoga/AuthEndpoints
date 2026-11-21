using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>Connected apps: a user lists the clients they connected and disconnects one.</summary>
public sealed class OAuthConnectedAppTests
{
    private const string Route = "/oauth/authorizations";

    [Fact]
    public async Task The_list_shows_each_live_grant_of_the_signed_in_user()
    {
        await using var host = await StartAsync(options =>
        {
            options.RecordLastUsed = true;
            options.ScopeDefinitions.Add(new OAuthScopeDefinition { Name = "api", DisplayName = "Use the API", Description = "Read and write your data." });
        });
        var (user, _) = await host.UserAsync("list");
        var (other, _) = await host.UserAsync("other");
        var (client, _) = await host.IssueAsync(user, resource: OtherResource, name: "Assistant");
        await host.IssueAsync(other, name: "Not mine");

        var list = await ListAsync(user);
        var item = Assert.Single(list.EnumerateArray());
        Assert.Equal(client.ClientId, item.GetProperty("clientId").GetString());
        Assert.Equal("Assistant", item.GetProperty("clientName").GetString());
        Assert.Equal(OAuthClientKinds.Dynamic, item.GetProperty("clientKind").GetString());
        Assert.Equal(JsonValueKind.Null, item.GetProperty("clientHost").ValueKind);
        Assert.Contains("api", item.GetProperty("scopes").EnumerateArray().Select(scope => scope.GetString()));
        var detail = item.GetProperty("scopeDetails").EnumerateArray().First(scope => scope.GetProperty("name").GetString() == "api");
        Assert.Equal("Use the API", detail.GetProperty("displayName").GetString());
        Assert.Equal(OtherResource, item.GetProperty("resource").GetString());
        Assert.True(item.GetProperty("createdAt").GetDateTimeOffset() > DateTimeOffset.UtcNow.AddMinutes(-5));
        Assert.True(item.GetProperty("lastUsedAt").GetDateTimeOffset() > DateTimeOffset.UtcNow.AddMinutes(-5));
        Assert.False(string.IsNullOrEmpty(item.GetProperty("authorizationId").GetString()));
    }

    [Fact]
    public async Task Last_used_is_null_when_not_recorded()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("nolast");
        await host.IssueAsync(user);

        var item = Assert.Single((await ListAsync(user)).EnumerateArray());
        Assert.Equal(JsonValueKind.Null, item.GetProperty("lastUsedAt").ValueKind);
    }

    [Fact]
    public async Task Disconnecting_revokes_the_grant_and_its_tokens_and_needs_a_csrf_token()
    {
        var log = new OAuthServerEventTests.EventLog();
        await using var host = await StartAsync(
            services: services => services.AddSingleton(log),
            server: server => server.AddServerEvents<OAuthServerEventTests.RecordingEvents>());
        var (user, userId) = await host.UserAsync("disconnect");
        var (client, tokens) = await host.IssueAsync(user);
        var id = Assert.Single((await ListAsync(user)).EnumerateArray()).GetProperty("authorizationId").GetString()!;

        var withoutCsrf = await user.DeleteAsync($"{Route}/{id}");
        Assert.Equal(HttpStatusCode.BadRequest, withoutCsrf.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.CallApiAsync(tokens.AccessToken)).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await DeleteAsync(user, id)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.CallApiAsync(tokens.AccessToken)).StatusCode);
        using var anon = host.Client(cookies: false);
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken))));
        Assert.Empty((await ListAsync(user)).EnumerateArray());
        Assert.Equal(HttpStatusCode.NotFound, (await DeleteAsync(user, id)).StatusCode);

        var revoked = Assert.Single(log.Of(OAuthServerEventType.AuthorizationRevoked));
        Assert.Equal(OAuthRevokedBy.User, revoked.RevokedBy);
        Assert.Equal(userId, revoked.UserId);
        Assert.Equal(id, revoked.AuthorizationId);
        Assert.Null(revoked.ActorId);
    }

    [Fact]
    public async Task Another_users_grant_cannot_be_revoked_and_looks_unknown()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var (intruder, _) = await host.UserAsync("intruder");
        var (_, tokens) = await host.IssueAsync(owner);
        var id = Assert.Single((await ListAsync(owner)).EnumerateArray()).GetProperty("authorizationId").GetString()!;

        Assert.Equal(HttpStatusCode.NotFound, (await DeleteAsync(intruder, id)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await DeleteAsync(intruder, "unknown-id")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.CallApiAsync(tokens.AccessToken)).StatusCode);
        Assert.Single((await ListAsync(owner)).EnumerateArray());
    }

    [Fact]
    public async Task An_oauth_access_token_cannot_list_or_revoke()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("token");
        var (_, tokens) = await host.IssueAsync(user);
        var id = Assert.Single((await ListAsync(user)).EnumerateArray()).GetProperty("authorizationId").GetString()!;

        using var api = host.Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.GetAsync(Route)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.DeleteAsync($"{Route}/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.CallApiAsync(tokens.AccessToken)).StatusCode);
    }

    [Fact]
    public async Task A_token_forwarded_by_a_policy_scheme_is_refused()
    {
        const string smart = "Smart";
        await using var host = await StartAsync(
            options => options.AuthenticationScheme = smart,
            services => services.AddAuthentication().AddPolicyScheme(smart, smart, policy => policy.ForwardDefaultSelector = http =>
                http.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.Ordinal)
                    ? OAuthServerConstants.AccessTokenScheme
                    : IdentityConstants.ApplicationScheme));
        var (user, _) = await host.UserAsync("smart");
        var (_, tokens) = await host.IssueAsync(user);
        var id = Assert.Single((await ListAsync(user)).EnumerateArray()).GetProperty("authorizationId").GetString()!;

        using var api = host.Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await api.GetAsync(Route)).StatusCode);
        // The group refuses delegated callers before the antiforgery check (allowBearer: false) runs.
        Assert.Equal(HttpStatusCode.Forbidden, (await api.DeleteAsync($"{Route}/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.CallApiAsync(tokens.AccessToken)).StatusCode);
        Assert.Single((await ListAsync(user)).EnumerateArray());
    }

    [Fact]
    public async Task Grants_whose_tokens_all_expired_are_not_listed()
    {
        var clock = new FakeTimeProvider(TimeProvider.System.GetUtcNow());
        await using var host = await StartAsync(services: services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(clock);
        });
        var (user, userId) = await host.UserAsync("expired");
        await host.IssueAsync(user);
        await using var scope = host.Services.CreateAsyncScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOAuthConnectedAppService>();
        Assert.Single(await apps.ListAsync(userId));

        // Past the refresh token lifetime (30 days). The cookie has expired too, so ask the service.
        clock.Advance(TimeSpan.FromDays(31));
        Assert.Empty(await apps.ListAsync(userId));
    }

    [Fact]
    public async Task An_admin_lists_and_revokes_through_the_service_and_the_event_names_the_admin()
    {
        var log = new OAuthServerEventTests.EventLog();
        await using var host = await StartAsync(
            services: services => services.AddSingleton(log),
            server: server => server.AddServerEvents<OAuthServerEventTests.RecordingEvents>());
        var (user, userId) = await host.UserAsync("member");
        var (_, tokens) = await host.IssueAsync(user);

        await using (var scope = host.Services.CreateAsyncScope())
        {
            var apps = scope.ServiceProvider.GetRequiredService<IOAuthConnectedAppService>();
            var app = Assert.Single(await apps.ListAsync(userId));
            Assert.False(await apps.RevokeAsync("someone-else", app.AuthorizationId, OAuthRevokedBy.Admin, "admin-1"));
            Assert.True(await apps.RevokeAsync(userId, app.AuthorizationId, OAuthRevokedBy.Admin, "admin-1"));
            Assert.Empty(await apps.ListAsync(userId));
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.CallApiAsync(tokens.AccessToken)).StatusCode);
        var revoked = Assert.Single(log.Of(OAuthServerEventType.AuthorizationRevoked));
        Assert.Equal(OAuthRevokedBy.Admin, revoked.RevokedBy);
        Assert.Equal("admin-1", revoked.ActorId);
        Assert.Equal(userId, revoked.UserId);
    }

    [Fact]
    public async Task The_list_uses_the_registered_scope_descriptions()
    {
        await using var host = await StartAsync(
            options => options.ScopeDefinitions.Add(new OAuthScopeDefinition { Name = "api", DisplayName = "From options" }),
            server: server => server.AddScopeDescriptions<StoredScopeDescriptions>());
        var (user, _) = await host.UserAsync("described");
        await host.IssueAsync(user);

        var item = Assert.Single((await ListAsync(user)).EnumerateArray());
        var detail = item.GetProperty("scopeDetails").EnumerateArray().First(scope => scope.GetProperty("name").GetString() == "api");
        Assert.Equal("From the store: api", detail.GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task Grants_issued_for_another_subject_belong_to_the_approving_user()
    {
        await using var host = await StartAsync(server: server => server.AddPrincipalFactory<SharedSubject>());
        var (first, _) = await host.UserAsync("first");
        var (second, _) = await host.UserAsync("second");
        await host.IssueAsync(first, name: "First's client");
        await host.IssueAsync(second, name: "Second's client");

        Assert.Equal("First's client", Assert.Single((await ListAsync(first)).EnumerateArray()).GetProperty("clientName").GetString());
        var id = Assert.Single((await ListAsync(second)).EnumerateArray()).GetProperty("authorizationId").GetString()!;
        Assert.Equal(HttpStatusCode.NotFound, (await DeleteAsync(first, id)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await DeleteAsync(second, id)).StatusCode);
    }

    [Fact]
    public async Task Developer_apps_and_metadata_document_clients_show_their_host()
    {
        const string clientUrl = "https://assistant.example/oauth/client.json";
        var documents = new OAuthClientMetadataDocumentTests.FakeDocumentServer();
        documents.Serve(clientUrl, JsonSerializer.Serialize(new { client_id = clientUrl, client_name = "Doc assistant", redirect_uris = new[] { Loopback } }));
        await using var host = await StartAsync(
            options => options.ClientMetadataDocuments.Enabled = true,
            services =>
            {
                services.AddHttpClient(OAuthClientMetadataFetcher.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => documents);
                services.RemoveAll<IOAuthClientMetadataDnsResolver>();
                services.AddSingleton<IOAuthClientMetadataDnsResolver>(new PublicDns());
            });
        var (_, ownerId) = await host.UserAsync("dev");
        var (user, _) = await host.UserAsync("user");
        string devClientId;
        await using (var scope = host.Services.CreateAsyncScope())
        {
            devClientId = (await scope.ServiceProvider.GetRequiredService<IOAuthDeveloperAppService>().CreateAsync(
                ownerId, new OAuthDeveloperAppInput("Dev tool", "https://tools.example/about", null, [Loopback]), confidential: false)).App!.ClientId;
        }

        foreach (var clientId in new[] { clientUrl, devClientId })
        {
            var pkce = Pkce.Create();
            var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, clientId, Loopback, pkce.Challenge));
            using var anon = host.Client(cookies: false);
            await ReadTokenAsync(await TokenAsync(anon, CodeGrant(clientId, Loopback, approved["code"], pkce.Verifier)));
        }

        var items = (await ListAsync(user)).EnumerateArray().ToDictionary(item => item.GetProperty("clientId").GetString()!);
        Assert.Equal(OAuthClientKinds.MetadataDocument, items[clientUrl].GetProperty("clientKind").GetString());
        Assert.Equal("assistant.example", items[clientUrl].GetProperty("clientHost").GetString());
        Assert.Equal(OAuthClientKinds.DeveloperApp, items[devClientId].GetProperty("clientKind").GetString());
        Assert.Equal("tools.example", items[devClientId].GetProperty("clientHost").GetString());
        Assert.Equal("Dev tool", items[devClientId].GetProperty("clientName").GetString());
    }

    [Fact]
    public async Task A_seeded_client_is_listed_as_configured()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("seeded");
        var pkce = Pkce.Create();
        var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, SeededClientId, SeededRedirect, pkce.Challenge));
        using var anon = host.Client(cookies: false);
        await ReadTokenAsync(await TokenAsync(anon, CodeGrant(SeededClientId, SeededRedirect, approved["code"], pkce.Verifier)));

        var item = Assert.Single((await ListAsync(user)).EnumerateArray());
        Assert.Equal(OAuthClientKinds.Configured, item.GetProperty("clientKind").GetString());
        Assert.Equal("Seeded SPA", item.GetProperty("clientName").GetString());
    }

    [Fact]
    public async Task MapOAuthServer_maps_the_routes_unless_turned_off_or_moved()
    {
        await using (var host = await StartAsync(recipe: true))
        {
            var (user, _) = await host.UserAsync("recipe");
            Assert.Equal(HttpStatusCode.OK, (await user.GetAsync(Route)).StatusCode);
        }

        await using (var host = await StartAsync(recipe: true, endpoints: parts => parts.ConnectedApps = false))
        {
            var (user, _) = await host.UserAsync("off");
            Assert.Equal(HttpStatusCode.NotFound, (await user.GetAsync(Route)).StatusCode);
        }

        await using (var host = await StartAsync(recipe: true, endpoints: parts => parts.ConnectedAppsPrefix = "/account/connected-apps"))
        {
            var (user, _) = await host.UserAsync("moved");
            Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/account/connected-apps")).StatusCode);
        }

        await Assert.ThrowsAsync<ArgumentException>(() => StartAsync(recipe: true, endpoints: parts => parts.ConnectedAppsPrefix = "oauth"));
    }

    private static async Task<JsonElement> ListAsync(HttpClient user)
    {
        var response = await user.GetAsync(Route);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode} {text}");
        return JsonSerializer.Deserialize<JsonElement>(text);
    }

    private static async Task<HttpResponseMessage> DeleteAsync(HttpClient user, string id)
    {
        var csrf = await user.GetFromJsonAsync<JsonElement>("/test/csrf");
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"{Route}/{id}");
        request.Headers.Add(CsrfHeader, csrf.GetProperty("token").GetString());
        return await user.SendAsync(request);
    }

    private sealed class StoredScopeDescriptions : IOAuthScopeDescriptions
    {
        public ValueTask<IReadOnlyList<OAuthScopeDetail>> DescribeAsync(
            IReadOnlyList<string> scopes, System.Globalization.CultureInfo culture, CancellationToken cancellationToken)
            => ValueTask.FromResult<IReadOnlyList<OAuthScopeDetail>>(
                scopes.Select(scope => new OAuthScopeDetail(scope, $"From the store: {scope}", null)).ToList());
    }

    private sealed class SharedSubject : IOAuthPrincipalFactory
    {
        public ValueTask<System.Security.Claims.ClaimsPrincipal?> CreateAsync(OAuthPrincipalContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult<System.Security.Claims.ClaimsPrincipal?>(OAuthPrincipals.ForSubject("shared-service-account"));
    }

    private sealed class PublicDns : IOAuthClientMetadataDnsResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
            => Task.FromResult(new[] { IPAddress.Parse("93.184.215.14") });
    }
}
