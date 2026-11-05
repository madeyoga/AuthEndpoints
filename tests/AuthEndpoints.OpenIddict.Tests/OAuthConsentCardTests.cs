using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>Developer app details on the consent card (homepage, description, client type, owner).</summary>
public sealed class OAuthConsentCardTests
{
    private const string WebRedirect = "https://dev.example/callback";
    private static readonly string[] DeveloperAppFields = ["homepageUrl", "description", "confidential", "owner"];

    [Fact]
    public async Task A_developer_app_card_shows_homepage_description_and_client_type_but_no_owner_by_default()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var clientId = await CreateAppAsync(owner, "Server app", "https://dev.example/home", "Syncs your notes.", confidential: true);
        var (user, _) = await host.UserAsync("user");

        var id = await OAuthTestHost.StartAsync(user, clientId, WebRedirect, Pkce.Create().Challenge);
        var card = await user.GetFromJsonAsync<JsonElement>($"/oauth/requests/{id}");

        Assert.Equal("Server app", card.GetProperty("clientName").GetString());
        Assert.Equal("https://dev.example/home", card.GetProperty("homepageUrl").GetString());
        Assert.Equal("Syncs your notes.", card.GetProperty("description").GetString());
        Assert.True(card.GetProperty("confidential").GetBoolean());
        Assert.Equal(JsonValueKind.Null, card.GetProperty("owner").ValueKind);

        // Nothing about the owner's Identity account reaches the card.
        var text = await user.GetStringAsync($"/oauth/requests/{id}");
        Assert.DoesNotContain("owner-", text, StringComparison.Ordinal);
        Assert.DoesNotContain("@example.test", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_public_developer_app_without_a_description_shows_false_and_null()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var clientId = await CreateAppAsync(owner, "Desktop app", "https://dev.example", description: null, confidential: false);
        var (user, _) = await host.UserAsync("user");

        var id = await OAuthTestHost.StartAsync(user, clientId, WebRedirect, Pkce.Create().Challenge);
        var card = await user.GetFromJsonAsync<OAuthConsentCard>($"/oauth/requests/{id}");

        Assert.Equal("https://dev.example", card!.HomepageUrl);
        Assert.Null(card.Description);
        Assert.False(card.Confidential);
        Assert.Null(card.Owner);
    }

    [Fact]
    public async Task Seeded_and_dynamically_registered_clients_show_null_for_every_developer_app_field()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("user");
        var dynamic = await host.RegisterAsync("Dynamic client");

        var seededId = await OAuthTestHost.StartAsync(user, SeededClientId, SeededRedirect, Pkce.Create().Challenge);
        var dynamicId = await OAuthTestHost.StartAsync(user, dynamic.ClientId, dynamic.RedirectUri, Pkce.Create().Challenge);

        foreach (var id in new[] { seededId, dynamicId })
        {
            var card = await user.GetFromJsonAsync<JsonElement>($"/oauth/requests/{id}");
            foreach (var field in DeveloperAppFields)
            {
                Assert.Equal(JsonValueKind.Null, card.GetProperty(field).ValueKind);
            }
        }
    }

    [Fact]
    public async Task A_registered_owner_display_names_the_owner_and_is_only_asked_about_developer_apps()
    {
        var display = new RecordingOwnerDisplay();
        await using var host = await StartAsync(
            services: services => services.AddSingleton(display),
            server: oauth => oauth.AddDeveloperAppOwnerDisplay<RecordingOwnerDisplay.Adapter>());
        var (owner, ownerId) = await host.UserAsync("owner");
        var clientId = await CreateAppAsync(owner, "Server app", "https://dev.example", "An app", confidential: false);
        var (user, _) = await host.UserAsync("user");
        display.Names[ownerId] = "  Example Labs  ";

        var appRequest = await OAuthTestHost.StartAsync(user, clientId, WebRedirect, Pkce.Create().Challenge);
        var card = await user.GetFromJsonAsync<OAuthConsentCard>($"/oauth/requests/{appRequest}");
        Assert.Equal("Example Labs", card!.Owner);
        var asked = Assert.Single(display.Calls);
        Assert.Equal(ownerId, asked.OwnerId);
        Assert.Equal(clientId, asked.ClientId);

        // Blank text shows nothing.
        display.Names[ownerId] = " ";
        card = await user.GetFromJsonAsync<OAuthConsentCard>($"/oauth/requests/{appRequest}");
        Assert.Null(card!.Owner);

        // Other clients never reach the display.
        display.Calls.Clear();
        var seeded = await OAuthTestHost.StartAsync(user, SeededClientId, SeededRedirect, Pkce.Create().Challenge);
        Assert.Null((await user.GetFromJsonAsync<OAuthConsentCard>($"/oauth/requests/{seeded}"))!.Owner);
        Assert.Empty(display.Calls);
    }

    [Fact]
    public async Task Details_are_read_when_the_card_is_fetched_while_the_client_name_stays_as_authorized()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var clientId = await CreateAppAsync(owner, "Server app", "https://dev.example/old", "Old text", confidential: false);
        var appId = await AppIdAsync(owner, clientId);
        var (user, _) = await host.UserAsync("user");
        var id = await OAuthTestHost.StartAsync(user, clientId, WebRedirect, Pkce.Create().Challenge);

        var edit = await SendAsync(owner, HttpMethod.Put, $"/oauth/apps/{appId}", new
        {
            name = "Renamed app",
            homepageUrl = "https://dev.example/new",
            description = "New text",
            redirectUris = new[] { WebRedirect },
        });
        Assert.Equal(HttpStatusCode.OK, edit.StatusCode);

        var card = await user.GetFromJsonAsync<OAuthConsentCard>($"/oauth/requests/{id}");
        Assert.Equal("Server app", card!.ClientName);
        Assert.Equal("https://dev.example/new", card.HomepageUrl);
        Assert.Equal("New text", card.Description);
    }

    [Fact]
    public async Task A_deleted_developer_app_makes_the_card_not_found()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var clientId = await CreateAppAsync(owner, "Server app", "https://dev.example", "An app", confidential: true);
        var appId = await AppIdAsync(owner, clientId);
        var (user, _) = await host.UserAsync("user");
        var id = await OAuthTestHost.StartAsync(user, clientId, WebRedirect, Pkce.Create().Challenge);

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(owner, HttpMethod.Delete, $"/oauth/apps/{appId}")).StatusCode);

        // The client is gone, so the request is no longer usable. The details are never shown as null for it.
        Assert.Equal(HttpStatusCode.NotFound, (await user.GetAsync($"/oauth/requests/{id}")).StatusCode);
    }

    [Fact]
    public async Task The_principal_factory_sees_the_same_details_on_approve()
    {
        var seen = new ConcurrentBag<OAuthPendingRequest>();
        await using var host = await StartAsync(
            services: services => services.AddSingleton(seen),
            server: oauth => oauth.AddPrincipalFactory<CapturingPrincipalFactory>());
        var (owner, _) = await host.UserAsync("owner");
        var clientId = await CreateAppAsync(owner, "Server app", "https://dev.example", "An app", confidential: false);
        var (user, _) = await host.UserAsync("user");

        await ApproveAsync(user, await OAuthTestHost.StartAsync(user, clientId, WebRedirect, Pkce.Create().Challenge));

        var request = Assert.Single(seen);
        Assert.Equal("https://dev.example", request.HomepageUrl);
        Assert.Equal("An app", request.Description);
        Assert.False(request.Confidential);
        Assert.Null(request.Owner);
    }

    private static async Task<string> CreateAppAsync(
        HttpClient owner, string name, string homepageUrl, string? description, bool confidential)
    {
        var response = await SendAsync(owner, HttpMethod.Post, "/oauth/apps", new
        {
            name,
            homepageUrl,
            description,
            redirectUris = new[] { WebRedirect },
            confidential,
        });
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.Created, text);
        return JsonSerializer.Deserialize<JsonElement>(text).GetProperty("app").GetProperty("clientId").GetString()!;
    }

    private static async Task<Guid> AppIdAsync(HttpClient owner, string clientId)
    {
        var apps = await owner.GetFromJsonAsync<JsonElement>("/oauth/apps");
        return apps.EnumerateArray().Single(app => app.GetProperty("clientId").GetString() == clientId).GetProperty("id").GetGuid();
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient owner, HttpMethod method, string path, object? body = null)
    {
        var csrf = await owner.GetFromJsonAsync<JsonElement>("/test/csrf");
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Add(CsrfHeader, csrf.GetProperty("token").GetString());
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return await owner.SendAsync(request);
    }

    private sealed class RecordingOwnerDisplay
    {
        public ConcurrentDictionary<string, string> Names { get; } = new(StringComparer.Ordinal);

        public List<OAuthDeveloperAppOwnerContext> Calls { get; } = [];

        public sealed class Adapter(RecordingOwnerDisplay inner) : IOAuthDeveloperAppOwnerDisplay
        {
            public ValueTask<string?> GetOwnerAsync(OAuthDeveloperAppOwnerContext context, CancellationToken cancellationToken)
            {
                lock (inner.Calls)
                {
                    inner.Calls.Add(context);
                }

                return ValueTask.FromResult(inner.Names.GetValueOrDefault(context.OwnerId));
            }
        }
    }

    private sealed class CapturingPrincipalFactory(ConcurrentBag<OAuthPendingRequest> seen) : IOAuthPrincipalFactory
    {
        public ValueTask<ClaimsPrincipal?> CreateAsync(OAuthPrincipalContext context, CancellationToken cancellationToken)
        {
            seen.Add(context.Request);
            return ValueTask.FromResult<ClaimsPrincipal?>(OAuthPrincipals.ForSubject(context.UserId));
        }
    }
}
