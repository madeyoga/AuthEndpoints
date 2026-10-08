using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AuthEndpoints.External.OAuth.Tests;

public class OAuthFlowTests : IClassFixture<OAuthFlowTests.Host>
{
    private readonly Host _factory;

    public OAuthFlowTests(Host factory) => _factory = factory;

    [Fact]
    public async Task Verified_callback_creates_user_and_clears_external_cookie()
    {
        var client = CreateClient();
        await SeedExternalAsync(client, "new-user@example.com", verified: true, key: "key-1");

        var callback = await client.GetAsync("/auth/external/login/fake/callback?returnUrl=%2Fdashboard");

        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/dashboard", callback.Headers.Location?.ToString());
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/test/external-info")).StatusCode);
    }

    [Fact]
    public async Task Missing_email_clears_external_cookie()
    {
        var client = CreateClient();
        await SeedExternalAsync(client, email: null, verified: false, key: "key-missing");

        var callback = await client.GetAsync("/auth/external/login/fake/callback");

        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Contains("error=email_missing", callback.Headers.Location?.OriginalString, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/test/external-info")).StatusCode);
    }

    [Fact]
    public async Task Callback_rejects_a_ticket_for_a_different_provider()
    {
        var client = CreateClient();
        await SeedExternalAsync(client, "other@example.com", verified: true, key: "key-other", provider: "GitHub");

        var callback = await client.GetAsync("/auth/external/login/fake/callback");

        Assert.Contains("error=provider_mismatch", callback.Headers.Location?.OriginalString, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/test/external-info")).StatusCode);
    }

    [Fact]
    public async Task Auto_link_off_does_not_attach_an_existing_email()
    {
        var client = CreateClient();
        await client.PostAsJsonAsync("/test/user", new { email = "exists@example.com", password = "Passw0rd", emailConfirmed = true });
        await SeedExternalAsync(client, "exists@example.com", verified: true, key: "key-exists");

        var callback = await client.GetAsync("/auth/external/login/fake/callback");

        Assert.Contains("error=auto_link_disabled", callback.Headers.Location?.OriginalString, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Link_challenge_stores_the_signed_in_user_id()
    {
        var client = CreateClient();
        var created = await client.PostAsJsonAsync("/test/user", new { email = "link@example.com", password = "Passw0rd", emailConfirmed = true });
        var body = await created.Content.ReadFromJsonAsync<IdBody>();
        await client.PostAsync("/test/signin?email=link@example.com", null);

        var start = await client.GetAsync("/auth/external/link/Fake");
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);

        var challenge = await client.GetFromJsonAsync<ChallengeBody>("/test/challenge");
        Assert.Equal(body!.Id, challenge!.Xsrf);
    }

    [Fact]
    public async Task Link_callback_rejects_a_planted_external_cookie()
    {
        var client = CreateClient();
        await client.PostAsJsonAsync("/test/user", new { email = "victim@example.com", password = "Passw0rd", emailConfirmed = true });
        await client.PostAsync("/test/signin?email=victim@example.com", null);
        await SeedExternalAsync(client, "attacker@example.com", verified: true, key: "atk", xsrf: "someone-else");

        var callback = await client.GetAsync("/auth/external/link/Fake/callback");

        Assert.Contains("error=external_login_info_missing", callback.Headers.Location?.OriginalString, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/test/external-info")).StatusCode);
    }

    [Fact]
    public async Task Unlink_requires_antiforgery_and_reauth_and_refuses_the_last_method()
    {
        var client = CreateClient();
        var created = await client.PostAsJsonAsync("/test/user", new { email = "only@example.com", password = (string?)null, emailConfirmed = true });
        var only = await created.Content.ReadFromJsonAsync<IdBody>();
        await client.PostAsync("/test/signin?email=only@example.com", null);
        await SeedExternalAsync(client, "only@example.com", verified: true, key: "only-key", xsrf: only!.Id);
        var linked = await client.GetAsync("/auth/external/link/Fake/callback");
        Assert.Equal(HttpStatusCode.Redirect, linked.StatusCode);

        var csrfBeforeReauth = await client.GetFromJsonAsync<CsrfBody>("/test/csrf");
        var noReauth = new HttpRequestMessage(HttpMethod.Delete, "/auth/external/logins/Fake/only-key");
        noReauth.Headers.Add("RequestVerificationToken", csrfBeforeReauth!.Token);
        var bare = await client.SendAsync(noReauth);
        Assert.Equal(HttpStatusCode.Forbidden, bare.StatusCode);

        await client.PostAsync("/test/reauth", null);
        var noCsrf = await client.DeleteAsync("/auth/external/logins/Fake/only-key");
        Assert.Equal(HttpStatusCode.BadRequest, noCsrf.StatusCode);

        var csrf = await client.GetFromJsonAsync<CsrfBody>("/test/csrf");
        var withReauth = new HttpRequestMessage(HttpMethod.Delete, "/auth/external/logins/Fake/only-key");
        withReauth.Headers.Add("RequestVerificationToken", csrf!.Token);
        var lastMethod = await client.SendAsync(withReauth);
        var lastBody = await lastMethod.Content.ReadAsStringAsync();
        Assert.True(lastMethod.StatusCode == HttpStatusCode.BadRequest, lastBody);
        Assert.Contains("last_signin_method", lastBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unlink_succeeds_when_a_password_remains()
    {
        var client = CreateClient();
        var created = await client.PostAsJsonAsync("/test/user", new { email = "both@example.com", password = "Passw0rd", emailConfirmed = true });
        var both = await created.Content.ReadFromJsonAsync<IdBody>();
        await client.PostAsync("/test/signin?email=both@example.com", null);
        await SeedExternalAsync(client, "both@example.com", verified: true, key: "both-key", xsrf: both!.Id);
        Assert.Equal(HttpStatusCode.Redirect, (await client.GetAsync("/auth/external/link/Fake/callback")).StatusCode);

        var csrf = await client.GetFromJsonAsync<CsrfBody>("/test/csrf");
        await client.PostAsync("/test/reauth", null);
        var request = new HttpRequestMessage(HttpMethod.Delete, "/auth/external/logins/Fake/both-key");
        request.Headers.Add("RequestVerificationToken", csrf!.Token);
        var response = await client.SendAsync(request);
        Assert.True(response.StatusCode == HttpStatusCode.NoContent, await response.Content.ReadAsStringAsync());
    }

    private static async Task SeedExternalAsync(
        HttpClient client,
        string? email,
        bool verified,
        string key,
        string provider = "Fake",
        string? xsrf = null)
    {
        var response = await client.PostAsJsonAsync("/test/external-cookie", new
        {
            provider,
            key,
            email,
            verified,
            xsrf,
        });
        response.EnsureSuccessStatusCode();
    }

    private HttpClient CreateClient()
    {
        var client = _factory.CreateClient(NoRedirect);
        var origin = client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        client.DefaultRequestHeaders.TryAddWithoutValidation("Origin", origin);
        return client;
    }

    private static WebApplicationFactoryClientOptions NoRedirect { get; } = new()
    {
        AllowAutoRedirect = false,
        HandleCookies = true,
    };

    private sealed record IdBody(string Id);
    private sealed record CsrfBody(string Token);
    private sealed record ChallengeBody(string? Xsrf);

    public sealed class Host : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseContentRoot(AppContext.BaseDirectory);
        }

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.UseContentRoot(AppContext.BaseDirectory);
            return base.CreateHost(builder);
        }
    }
}
