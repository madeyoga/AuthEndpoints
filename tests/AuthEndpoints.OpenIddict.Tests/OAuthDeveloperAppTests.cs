using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

public sealed class OAuthDeveloperAppTests
{
    private const string WebRedirect = "https://dev.example/callback";
    private const string NativeRedirect = "com.example.app:/callback";

    [Fact]
    public async Task Confidential_app_gets_a_secret_once_and_must_use_it_at_the_token_endpoint()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");

        var response = await CreateAsync(owner, App("Server app", [WebRedirect], confidential: true));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var created = await response.Content.ReadFromJsonAsync<JsonElement>();
        var app = created.GetProperty("app");
        var clientId = app.GetProperty("clientId").GetString()!;
        var secret = created.GetProperty("clientSecret").GetString()!;
        Assert.True(secret.Length >= 43);
        Assert.True(app.GetProperty("confidential").GetBoolean());
        Assert.Equal("Active", app.GetProperty("status").GetString());
        Assert.Equal(response.Headers.Location!.ToString(), $"/oauth/apps/{app.GetProperty("id").GetString()}");

        // The secret is never shown again, and only its hash is stored.
        var listed = await owner.GetStringAsync("/oauth/apps");
        Assert.DoesNotContain(secret, listed, StringComparison.Ordinal);
        Assert.DoesNotContain("clientSecret", listed, StringComparison.Ordinal);
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var stored = await applications.FindByClientIdAsync(clientId);
            Assert.Equal(OpenIddictConstants.ClientTypes.Confidential, await applications.GetClientTypeAsync(stored!));
            Assert.True(await applications.ValidateClientSecretAsync(stored!, secret));
        }

        var (user, userId) = await host.UserAsync("user");
        var pkce = Pkce.Create();
        var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, clientId, WebRedirect, pkce.Challenge));
        using var anon = host.Client(cookies: false);
        var withoutSecret = CodeGrant(clientId, WebRedirect, approved["code"], pkce.Verifier);
        Assert.Equal("invalid_client", await ClientErrorAsync(await TokenAsync(anon, withoutSecret)));

        var withSecret = CodeGrant(clientId, WebRedirect, approved["code"], pkce.Verifier);
        withSecret["client_secret"] = secret;
        var tokens = await ReadTokenAsync(await TokenAsync(anon, withSecret));
        Assert.Equal(userId, await host.SubjectAsync(tokens.AccessToken));
    }

    [Fact]
    public async Task Confidential_app_still_requires_pkce()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var (clientId, secret) = await CreateOkAsync(owner, App("Server app", [WebRedirect], confidential: true));
        var (user, _) = await host.UserAsync("user");

        var response = await user.GetAsync(AuthorizeUrl(clientId, WebRedirect, challenge: null, method: null));

        Assert.NotEqual(ConsentUrl, response.Headers.Location?.GetLeftPart(UriPartial.Path));
        Assert.NotNull(secret);
    }

    [Fact]
    public async Task Rotating_the_secret_stops_the_old_one()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var (clientId, oldSecret) = await CreateOkAsync(owner, App("Server app", [WebRedirect], confidential: true));
        var id = await IdAsync(owner, clientId);
        var (user, _) = await host.UserAsync("user");
        var pkce = Pkce.Create();
        var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, clientId, WebRedirect, pkce.Challenge));
        using var anon = host.Client(cookies: false);
        var grant = CodeGrant(clientId, WebRedirect, approved["code"], pkce.Verifier);
        grant["client_secret"] = oldSecret!;
        var tokens = await ReadTokenAsync(await TokenAsync(anon, grant));

        var rotated = await SendAsync(owner, HttpMethod.Post, $"/oauth/apps/{id}/secret");
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        Assert.Equal("no-store", rotated.Headers.CacheControl?.ToString());
        var newSecret = (await rotated.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("clientSecret").GetString()!;
        Assert.NotEqual(oldSecret, newSecret);

        var stale = RefreshGrant(clientId, tokens.RefreshToken);
        stale["client_secret"] = oldSecret!;
        Assert.Equal("invalid_client", await ClientErrorAsync(await TokenAsync(anon, stale)));
        var fresh = RefreshGrant(clientId, tokens.RefreshToken);
        fresh["client_secret"] = newSecret;
        await ReadTokenAsync(await TokenAsync(anon, fresh));
    }

    [Fact]
    public async Task Public_app_uses_pkce_only_and_may_use_a_private_use_scheme()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var response = await CreateAsync(owner, App("Desktop app", [NativeRedirect, Loopback]));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(JsonValueKind.Null, created.GetProperty("clientSecret").ValueKind);
        var app = created.GetProperty("app");
        Assert.False(app.GetProperty("confidential").GetBoolean());
        Assert.Equal([NativeRedirect, Loopback], app.GetProperty("redirectUris").EnumerateArray().Select(uri => uri.GetString()));
        var clientId = app.GetProperty("clientId").GetString()!;

        var (user, userId) = await host.UserAsync("user");
        var pkce = Pkce.Create();
        var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, clientId, NativeRedirect, pkce.Challenge));
        using var anon = host.Client(cookies: false);
        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(clientId, NativeRedirect, approved["code"], pkce.Verifier)));
        Assert.Equal(userId, await host.SubjectAsync(tokens.AccessToken));

        var rotate = await SendAsync(owner, HttpMethod.Post, $"/oauth/apps/{app.GetProperty("id").GetString()}/secret");
        Assert.Equal(HttpStatusCode.BadRequest, rotate.StatusCode);
    }

    [Theory]
    [InlineData(true, NativeRedirect)]
    [InlineData(true, "http://dev.example/callback")]
    [InlineData(false, "http://dev.example/callback")]
    [InlineData(false, "javascript:alert(1)")]
    [InlineData(false, "data:text/html,hi")]
    [InlineData(false, "file:///etc/passwd")]
    [InlineData(false, "myapp:/callback")]
    [InlineData(false, ".example:/callback")]
    [InlineData(false, WebRedirect + "#fragment")]
    [InlineData(false, "https://user:pw@dev.example/callback")]
    [InlineData(false, "/relative/callback")]
    public async Task Bad_redirect_uris_are_rejected(bool confidential, string redirect)
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");

        var errors = await ValidationErrorsAsync(await CreateAsync(owner, App("App", [redirect], confidential)));

        Assert.True(errors.TryGetProperty("redirectUris", out _), errors.ToString());
    }

    [Fact]
    public async Task Missing_or_oversized_fields_are_rejected()
    {
        await using var host = await StartAsync(options => options.DeveloperApps.MaxRedirectUris = 2);
        var (owner, _) = await host.UserAsync("owner");

        var errors = await ValidationErrorsAsync(await CreateAsync(owner, new
        {
            name = " ",
            homepageUrl = "ftp://dev.example",
            description = new string('x', 1001),
            redirectUris = new[] { WebRedirect, Loopback, NativeRedirect },
        }));

        Assert.Equal(["description", "homepageUrl", "name", "redirectUris"], errors.EnumerateObject().Select(p => p.Name).Order());
        errors = await ValidationErrorsAsync(await CreateAsync(owner, new { name = "App", homepageUrl = "https://dev.example" }));
        Assert.True(errors.TryGetProperty("redirectUris", out _));
        Assert.Empty((await owner.GetFromJsonAsync<JsonElement>("/oauth/apps")).EnumerateArray());
    }

    [Fact]
    public async Task Owners_see_and_change_only_their_own_apps()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var (other, _) = await host.UserAsync("other");
        var (clientId, _) = await CreateOkAsync(owner, App("Mine", [WebRedirect], confidential: true));
        var id = await IdAsync(owner, clientId);

        Assert.Empty((await other.GetFromJsonAsync<JsonElement>("/oauth/apps")).EnumerateArray());
        Assert.Equal(HttpStatusCode.NotFound, (await other.GetAsync($"/oauth/apps/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(other, HttpMethod.Put, $"/oauth/apps/{id}", App("Taken", [WebRedirect]))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(other, HttpMethod.Post, $"/oauth/apps/{id}/secret")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(other, HttpMethod.Delete, $"/oauth/apps/{id}")).StatusCode);

        var mine = await owner.GetFromJsonAsync<JsonElement>($"/oauth/apps/{id}");
        Assert.Equal("Mine", mine.GetProperty("name").GetString());
        Assert.False(mine.TryGetProperty("ownerId", out _));
    }

    [Fact]
    public async Task Signed_out_callers_get_401_and_writes_need_a_csrf_token()
    {
        await using var host = await StartAsync();
        using var anon = host.Client(cookies: false);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/oauth/apps")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/oauth/apps", App("App", [WebRedirect]))).StatusCode);

        var (owner, _) = await host.UserAsync("owner");
        Assert.Equal(HttpStatusCode.BadRequest, (await owner.PostAsJsonAsync("/oauth/apps", App("App", [WebRedirect]))).StatusCode);
        Assert.Empty((await owner.GetFromJsonAsync<JsonElement>("/oauth/apps")).EnumerateArray());
    }

    [Fact]
    public async Task Apps_per_user_are_limited()
    {
        await using var host = await StartAsync(options => options.DeveloperApps.MaxAppsPerUser = 2);
        var (owner, _) = await host.UserAsync("owner");
        var (other, _) = await host.UserAsync("other");
        await CreateOkAsync(owner, App("One", [WebRedirect]));
        await CreateOkAsync(owner, App("Two", [WebRedirect]));

        Assert.Equal(HttpStatusCode.Conflict, (await CreateAsync(owner, App("Three", [WebRedirect]))).StatusCode);
        await CreateOkAsync(other, App("Other", [WebRedirect]));
        Assert.Equal(2, (await owner.GetFromJsonAsync<JsonElement>("/oauth/apps")).GetArrayLength());
    }

    [Fact]
    public async Task Editing_replaces_redirects_and_keeps_the_client_type_and_secret()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var (clientId, secret) = await CreateOkAsync(owner, App("Before", [WebRedirect], confidential: true));
        var id = await IdAsync(owner, clientId);
        const string NewRedirect = "https://dev.example/new-callback";

        var updated = await SendAsync(owner, HttpMethod.Put, $"/oauth/apps/{id}", new
        {
            name = "After",
            homepageUrl = "https://dev.example/home",
            description = "Edited",
            redirectUris = new[] { NewRedirect },
            confidential = false,
        });
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        var app = await updated.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("After", app.GetProperty("name").GetString());
        Assert.Equal("Edited", app.GetProperty("description").GetString());
        Assert.True(app.GetProperty("confidential").GetBoolean());
        Assert.Equal([NewRedirect], app.GetProperty("redirectUris").EnumerateArray().Select(uri => uri.GetString()));

        // A confidential app still cannot list a private-use scheme after an edit.
        var errors = await ValidationErrorsAsync(await SendAsync(owner, HttpMethod.Put, $"/oauth/apps/{id}", App("After", [NativeRedirect])));
        Assert.True(errors.TryGetProperty("redirectUris", out _));

        var (user, _) = await host.UserAsync("user");
        var old = await user.GetAsync(AuthorizeUrl(clientId, WebRedirect, Pkce.Create().Challenge));
        Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        var pkce = Pkce.Create();
        var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, clientId, NewRedirect, pkce.Challenge));
        var grant = CodeGrant(clientId, NewRedirect, approved["code"], pkce.Verifier);
        grant["client_secret"] = secret!;
        using var anon = host.Client(cookies: false);
        await ReadTokenAsync(await TokenAsync(anon, grant));
    }

    [Fact]
    public async Task Deleting_an_app_revokes_its_tokens()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var (clientId, _) = await CreateOkAsync(owner, App("Public", [Loopback]));
        var id = await IdAsync(owner, clientId);
        var (user, _) = await host.UserAsync("user");
        var tokens = await IssuePublicAsync(host, user, clientId);

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(owner, HttpMethod.Delete, $"/oauth/apps/{id}")).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.CallApiAsync(tokens.AccessToken)).StatusCode);
        using var anon = host.Client(cookies: false);
        Assert.Equal("invalid_client", await ClientErrorAsync(await TokenAsync(anon, RefreshGrant(clientId, tokens.RefreshToken))));
        Assert.Equal(HttpStatusCode.NotFound, (await owner.GetAsync($"/oauth/apps/{id}")).StatusCode);
        await using var scope = host.Services.CreateAsyncScope();
        Assert.Null(await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().FindByClientIdAsync(clientId));
    }

    [Fact]
    public async Task Apps_wait_for_approval_and_disabling_revokes_their_tokens()
    {
        await using var host = await StartAsync(options => options.DeveloperApps.RequireApproval = true);
        var (owner, _) = await host.UserAsync("owner");
        var (clientId, _) = await CreateOkAsync(owner, App("Reviewed", [Loopback]));
        var id = await IdAsync(owner, clientId);
        var (user, _) = await host.UserAsync("user");

        Assert.Equal("PendingApproval", (await owner.GetFromJsonAsync<JsonElement>($"/oauth/apps/{id}")).GetProperty("status").GetString());
        var pending = await user.GetAsync(AuthorizeUrl(clientId, Loopback, Pkce.Create().Challenge));
        Assert.Equal("unauthorized_client", Query(pending.Headers.Location!.ToString())["error"]);

        await using (var scope = host.Services.CreateAsyncScope())
        {
            var apps = scope.ServiceProvider.GetRequiredService<IOAuthDeveloperAppService>();
            var queue = await apps.ListByStatusAsync(OAuthDeveloperAppStatus.PendingApproval);
            Assert.Equal(clientId, Assert.Single(queue).ClientId);
            Assert.True(await apps.SetStatusAsync(id, OAuthDeveloperAppStatus.Active));
            Assert.False(await apps.SetStatusAsync(Guid.NewGuid(), OAuthDeveloperAppStatus.Active));
        }

        var tokens = await IssuePublicAsync(host, user, clientId);
        await using (var scope = host.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IOAuthDeveloperAppService>().SetStatusAsync(id, OAuthDeveloperAppStatus.Disabled);
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.CallApiAsync(tokens.AccessToken)).StatusCode);
        // Disabling revoked the refresh token, so OpenIddict refuses it before the app check runs.
        using var anon = host.Client(cookies: false);
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(clientId, tokens.RefreshToken))));
        var disabled = await user.GetAsync(AuthorizeUrl(clientId, Loopback, Pkce.Create().Challenge));
        Assert.Equal("unauthorized_client", Query(disabled.Headers.Location!.ToString())["error"]);
    }

    [Fact]
    public async Task A_code_issued_before_disabling_cannot_be_exchanged()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var (clientId, _) = await CreateOkAsync(owner, App("Public", [Loopback]));
        var id = await IdAsync(owner, clientId);
        var (user, _) = await host.UserAsync("user");
        var pkce = Pkce.Create();
        var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, clientId, Loopback, pkce.Challenge));

        await using (var scope = host.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IOAuthDeveloperAppService>().SetStatusAsync(id, OAuthDeveloperAppStatus.Disabled);
        }

        using var anon = host.Client(cookies: false);
        var error = await ErrorAsync(await TokenAsync(anon, CodeGrant(clientId, Loopback, approved["code"], pkce.Verifier)));
        Assert.Contains(error, new[] { "unauthorized_client", "invalid_grant" });
    }

    [Fact]
    public async Task Deleting_the_owner_refuses_the_app_at_once_and_cleanup_removes_it()
    {
        await using var host = await StartAsync();
        var (owner, ownerId) = await host.UserAsync("owner");
        var (clientId, _) = await CreateOkAsync(owner, App("Orphan", [Loopback]));
        var (user, _) = await host.UserAsync("user");
        var tokens = await IssuePublicAsync(host, user, clientId);

        await using (var scope = host.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            Assert.True((await users.DeleteAsync((await users.FindByIdAsync(ownerId))!)).Succeeded);
        }

        using var anon = host.Client(cookies: false);
        Assert.Equal("unauthorized_client", await ErrorAsync(await TokenAsync(anon, RefreshGrant(clientId, tokens.RefreshToken))));
        var refused = await user.GetAsync(AuthorizeUrl(clientId, Loopback, Pkce.Create().Challenge));
        Assert.Equal("unauthorized_client", Query(refused.Headers.Location!.ToString())["error"]);

        var result = await host.Services.GetRequiredService<IOAuthServerCleanup>().SweepAsync();

        Assert.Equal(1, result.OrphanedDeveloperApps);
        Assert.Equal(0, result.UnusedClients);
        await using var check = host.Services.CreateAsyncScope();
        var applications = check.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync(clientId));
        Assert.NotNull(await applications.FindByClientIdAsync(SeededClientId));
    }

    [Fact]
    public async Task Cleanup_keeps_developer_apps_that_nobody_approved_yet()
    {
        await using var host = await StartAsync(options => options.DynamicRegistration.UnusedClientLifetime = TimeSpan.FromTicks(1));
        var (owner, _) = await host.UserAsync("owner");
        var (clientId, _) = await CreateOkAsync(owner, App("Unused", [Loopback]));

        var result = await host.Services.GetRequiredService<IOAuthServerCleanup>().SweepAsync();

        Assert.Equal(0, result.OrphanedDeveloperApps);
        Assert.Equal(0, result.UnusedClients);
        await using var scope = host.Services.CreateAsyncScope();
        Assert.NotNull(await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().FindByClientIdAsync(clientId));
    }

    private static object App(string name, string[] redirects, bool confidential = false) => new
    {
        name,
        homepageUrl = "https://dev.example",
        description = "A test app",
        redirectUris = redirects,
        confidential,
    };

    private static Task<HttpResponseMessage> CreateAsync(HttpClient owner, object body)
        => SendAsync(owner, HttpMethod.Post, "/oauth/apps", body);

    private static async Task<(string ClientId, string? Secret)> CreateOkAsync(HttpClient owner, object body)
    {
        var response = await CreateAsync(owner, body);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.Created, text);
        var json = JsonSerializer.Deserialize<JsonElement>(text);
        var secret = json.GetProperty("clientSecret");
        return (json.GetProperty("app").GetProperty("clientId").GetString()!,
            secret.ValueKind == JsonValueKind.Null ? null : secret.GetString());
    }

    private static async Task<Guid> IdAsync(HttpClient owner, string clientId)
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

    /// <summary>OpenIddict answers a failed client authentication with 401 and the error in the body.</summary>
    private static async Task<string> ClientErrorAsync(HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized, $"{(int)response.StatusCode} {text}");
        return JsonSerializer.Deserialize<JsonElement>(text).GetProperty("error").GetString()!;
    }

    private static async Task<JsonElement> ValidationErrorsAsync(HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, text);
        return JsonSerializer.Deserialize<JsonElement>(text).GetProperty("errors");
    }

    private static async Task<TokenPair> IssuePublicAsync(OAuthTestHost host, HttpClient user, string clientId)
    {
        var pkce = Pkce.Create();
        var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, clientId, Loopback, pkce.Challenge));
        using var anon = host.Client(cookies: false);
        return await ReadTokenAsync(await TokenAsync(anon, CodeGrant(clientId, Loopback, approved["code"], pkce.Verifier)));
    }
}
