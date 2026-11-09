using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

public sealed class OAuthFlowTests
{
    [Fact]
    public async Task Code_and_pkce_issue_tokens_whose_subject_is_the_signed_in_user()
    {
        await using var host = await StartAsync();
        var (user, userId) = await host.UserAsync("flow");
        var client = await host.RegisterAsync("Flow");
        var pkce = Pkce.Create();

        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge, "state-1");
        var approved = await ApproveAsync(user, id);
        Assert.Equal("state-1", approved["state"]);
        Assert.Equal(Issuer, approved["iss"]);

        using var anon = host.Client(cookies: false);
        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, approved["code"], pkce.Verifier)));
        Assert.Equal("Bearer", tokens.Body.GetProperty("token_type").GetString());
        Assert.Equal("api offline_access", tokens.Body.GetProperty("scope").GetString());
        Assert.True(tokens.Body.GetProperty("expires_in").GetInt32() <= 15 * 60);
        Assert.Equal(userId, await host.SubjectAsync(tokens.AccessToken));
    }

    [Fact]
    public async Task A_reused_code_and_a_mismatched_redirect_uri_are_rejected()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("reuse");
        var client = await host.RegisterAsync("Reuse");
        var pkce = Pkce.Create();
        using var anon = host.Client(cookies: false);

        var first = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge));
        var mismatched = await TokenAsync(anon, CodeGrant(client.ClientId, "http://127.0.0.1:9/other", first["code"], pkce.Verifier));
        Assert.Equal("invalid_grant", await ErrorAsync(mismatched));

        var second = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge));
        await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, second["code"], pkce.Verifier)));
        var reused = await TokenAsync(anon, CodeGrant(client, second["code"], pkce.Verifier));
        Assert.Equal("invalid_grant", await ErrorAsync(reused));
    }

    [Fact]
    public async Task An_authorize_redirect_uri_that_is_not_registered_is_rejected_without_redirecting()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("redirect");
        var client = await host.RegisterAsync("Redirect");

        var response = await user.GetAsync(AuthorizeUrl(client.ClientId, "https://evil.example/callback", Pkce.Create().Challenge));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task Plain_or_missing_pkce_never_issues_a_token()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("pkce");
        var client = await host.RegisterAsync("PKCE");
        var pkce = Pkce.Create();
        using var anon = host.Client(cookies: false);

        var plain = await user.GetAsync(AuthorizeUrl(client.ClientId, client.RedirectUri, pkce.Verifier, method: "plain"));
        AssertClientError(plain);

        var missingChallenge = await user.GetAsync(AuthorizeUrl(client.ClientId, client.RedirectUri, null, method: null));
        AssertClientError(missingChallenge);

        var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge));
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, CodeGrant(client, approved["code"], pkce.Verifier + "nope"))));
        Assert.Equal("invalid_request", await ErrorAsync(await TokenAsync(anon, CodeGrant(client, approved["code"], null))));
    }

    [Fact]
    public async Task Signed_out_authorize_goes_to_login_and_resumes_after_sign_in()
    {
        await using var host = await StartAsync();
        var client = await host.RegisterAsync("Signed out");
        var pkce = Pkce.Create();
        using var browser = host.Client();

        var response = await browser.GetAsync(AuthorizeUrl(client.ClientId, client.RedirectUri, pkce.Challenge, "resume"));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(LoginUrl + "?returnUrl=", location, StringComparison.Ordinal);
        var returnUrl = Query(location)["returnUrl"];
        Assert.StartsWith("/connect/authorize?", returnUrl, StringComparison.Ordinal);

        (await browser.PostAsync($"/test/signin?email=resume-{Guid.NewGuid():N}@example.test", null)).EnsureSuccessStatusCode();
        var resumed = await browser.GetAsync(returnUrl);
        Assert.Equal(HttpStatusCode.Redirect, resumed.StatusCode);
        Assert.StartsWith(ConsentUrl + "?request=", resumed.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Prompt_none_never_shows_a_page()
    {
        await using var host = await StartAsync();
        var client = await host.RegisterAsync("Prompt");
        using var anon = host.Client();
        var (user, _) = await host.UserAsync("prompt");

        var signedOut = await anon.GetAsync(AuthorizeUrl(client.ClientId, client.RedirectUri, Pkce.Create().Challenge, prompt: "none"));
        Assert.Equal("login_required", Query(signedOut.Headers.Location!.ToString())["error"]);

        var signedIn = await user.GetAsync(AuthorizeUrl(client.ClientId, client.RedirectUri, Pkce.Create().Challenge, prompt: "none"));
        Assert.Equal("consent_required", Query(signedIn.Headers.Location!.ToString())["error"]);
    }

    [Fact]
    public async Task Unknown_scopes_fail_and_omitted_scopes_get_the_defaults()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("scopes");
        var client = await host.RegisterAsync("Scopes", scope: "api profile");

        var unknown = await user.GetAsync(AuthorizeUrl(client.ClientId, client.RedirectUri, Pkce.Create().Challenge, scope: "admin"));
        Assert.Equal("invalid_scope", await AuthorizeErrorAsync(unknown));

        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge, scope: null);
        var card = await user.GetFromJsonAsync<OAuthConsentCard>($"/oauth/requests/{id}");
        Assert.Equal(["api", "offline_access"], card!.Scopes);
        Assert.Equal("Scopes", card.ClientName);
        Assert.Equal("127.0.0.1:9", card.RedirectHost);
        Assert.Equal(Audience, card.Resource);
    }

    [Fact]
    public async Task Refresh_rotates_with_no_reuse_and_revocation_kills_the_refresh_token()
    {
        await using var host = await StartAsync();
        var (user, userId) = await host.UserAsync("rotate");
        var (client, issued) = await host.IssueAsync(user);
        using var anon = host.Client(cookies: false);

        var rotated = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, issued.RefreshToken)));
        Assert.NotEqual(issued.RefreshToken, rotated.RefreshToken);
        Assert.NotEqual(issued.AccessToken, rotated.AccessToken);
        Assert.Equal(userId, await host.SubjectAsync(rotated.AccessToken));

        var reused = await TokenAsync(anon, RefreshGrant(client.ClientId, issued.RefreshToken));
        Assert.Equal("invalid_grant", await ErrorAsync(reused));

        var revoke = await anon.PostAsync("/connect/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = rotated.RefreshToken,
            ["token_type_hint"] = "refresh_token",
            ["client_id"] = client.ClientId,
        }));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, rotated.RefreshToken))));
    }

    [Fact]
    public async Task Revoking_the_authorization_kills_the_access_token_and_the_refresh_token()
    {
        await using var host = await StartAsync();
        var (user, userId) = await host.UserAsync("revoke");
        var client = await host.RegisterAsync("Revoke");
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge);

        string? authorizationId = null;
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var http = new Microsoft.AspNetCore.Http.DefaultHttpContext { RequestServices = scope.ServiceProvider };
            scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Http.IHttpContextAccessor>().HttpContext = http;
            var result = await scope.ServiceProvider.GetRequiredService<IOAuthConsentService>().ApproveAsync(id, userId);
            Assert.Equal(OAuthConsentStatus.Approved, result.Status);
            authorizationId = result.AuthorizationId;
            var code = Query(result.RedirectUrl!)["code"];
            using var anon = host.Client(cookies: false);
            var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, code, pkce.Verifier)));
            Assert.Equal(userId, await host.SubjectAsync(tokens.AccessToken));

            Assert.True(await scope.ServiceProvider.GetRequiredService<IOAuthConsentService>().RevokeAuthorizationAsync(authorizationId!));
            Assert.Equal(HttpStatusCode.Unauthorized, (await host.CallApiAsync(tokens.AccessToken)).StatusCode);
            Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken))));
        }
    }

    [Fact]
    public async Task A_token_for_another_resource_is_rejected_by_this_api_and_unknown_resources_fail()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("aud");
        var (_, other) = await host.IssueAsync(user, resource: OtherResource);

        var response = await host.CallApiAsync(other.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var client = await host.RegisterAsync("Evil");
        var evil = await user.GetAsync(AuthorizeUrl(client.ClientId, client.RedirectUri, Pkce.Create().Challenge, resource: "https://evil.example/api"));
        Assert.Equal("invalid_target", await AuthorizeErrorAsync(evil));
    }

    [Fact]
    public async Task Expired_access_tokens_fail_and_the_refresh_token_still_works()
    {
        var clock = new FakeTimeProvider(TimeProvider.System.GetUtcNow());
        await using var host = await StartAsync(
            options => options.AccessTokenLifetime = TimeSpan.FromMinutes(1),
            services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(clock);
            });
        var (user, userId) = await host.UserAsync("expiring");
        var (client, issued) = await host.IssueAsync(user);

        clock.Advance(TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.CallApiAsync(issued.AccessToken)).StatusCode);

        using var anon = host.Client(cookies: false);
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, issued.RefreshToken)));
        Assert.Equal(userId, await host.SubjectAsync(refreshed.AccessToken));
    }

    [Fact]
    public async Task Plain_http_is_rejected_by_default()
    {
        await using var host = await StartAsync();
        using var http = host.Client("http://localhost/", cookies: false);

        var metadata = await http.GetAsync(".well-known/oauth-authorization-server");
        Assert.Equal(HttpStatusCode.BadRequest, metadata.StatusCode);
        var token = await TokenAsync(http, RefreshGrant("x", "y"));
        Assert.Equal(HttpStatusCode.BadRequest, token.StatusCode);
    }

    [Fact]
    public async Task Seeded_clients_from_options_complete_the_flow()
    {
        await using var host = await StartAsync();
        var (user, userId) = await host.UserAsync("seeded");
        var pkce = Pkce.Create();

        var id = await OAuthTestHost.StartAsync(user, SeededClientId, SeededRedirect, pkce.Challenge);
        var card = await user.GetFromJsonAsync<OAuthConsentCard>($"/oauth/requests/{id}");
        Assert.Equal("Seeded SPA", card!.ClientName);
        var approved = await ApproveAsync(user, id);
        using var anon = host.Client(cookies: false);
        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(SeededClientId, SeededRedirect, approved["code"], pkce.Verifier)));
        Assert.Equal(userId, await host.SubjectAsync(tokens.AccessToken));

        // Seeding again updates in place.
        await host.Services.SeedOAuthClientsAsync();
    }

    private static void AssertClientError(HttpResponseMessage response)
    {
        var location = response.Headers.Location?.ToString() ?? "";
        Assert.DoesNotContain(ConsentUrl, location, StringComparison.Ordinal);
        if (response.StatusCode == HttpStatusCode.Redirect)
        {
            Assert.Contains("error=", location, StringComparison.Ordinal);
        }
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }
}
