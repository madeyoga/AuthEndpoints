using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using static AuthEndpoints.OpenIddict.Tests.OAuthOpenIdConnectTests;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>OpenID Connect logout (RP-initiated).</summary>
public sealed class OAuthLogoutTests
{
    private const string SignOutPage = "https://app.example/sign-out";

    [Fact]
    public async Task Logout_with_the_users_id_token_signs_out_and_returns_to_the_registered_uri_with_state()
    {
        await using var host = await StartOidcAsync();
        var (user, _) = await host.UserAsync("logout");
        var flow = await host.SignInAsync(user);

        var response = await user.GetAsync(Logout(IdToken(flow.Tokens), postLogout: PostLogout, state: "bye"));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(PostLogout, location, StringComparison.Ordinal);
        Assert.Equal("bye", Query(location)["state"]);
        Assert.False(await SignedInAsync(user));
    }

    [Fact]
    public async Task Logout_works_by_post_and_with_client_id_alongside_the_hint()
    {
        await using var host = await StartOidcAsync();
        var (user, _) = await host.UserAsync("logoutpost");
        var flow = await host.SignInAsync(user);

        var response = await user.PostAsync("/connect/logout", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["id_token_hint"] = IdToken(flow.Tokens),
            ["client_id"] = flow.Client.ClientId,
            ["post_logout_redirect_uri"] = PostLogout,
        }));

        Assert.StartsWith(PostLogout, response.Headers.Location?.ToString() ?? "", StringComparison.Ordinal);
        Assert.False(await SignedInAsync(user));
    }

    [Theory]
    [InlineData("https://evil.example/")]
    [InlineData("http://127.0.0.1:9/signed-out/other")]
    [InlineData("http://127.0.0.1:9/callback")] // a redirect_uri, not a post-logout URI
    public async Task An_unregistered_post_logout_redirect_uri_is_refused_and_the_user_stays_signed_in(string target)
    {
        await using var host = await StartOidcAsync();
        var (user, _) = await host.UserAsync("openredirect");
        var flow = await host.SignInAsync(user);

        var response = await user.GetAsync(Logout(IdToken(flow.Tokens), postLogout: target));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.True(await SignedInAsync(user));
    }

    [Fact]
    public async Task Another_clients_post_logout_uri_is_refused()
    {
        await using var host = await StartOidcAsync();
        var (user, _) = await host.UserAsync("crossclient");
        var flow = await host.SignInAsync(user, postLogoutRedirect: null);
        await host.RegisterOidcClientAsync("https://other-client.example/bye");

        var withHint = await user.GetAsync(Logout(IdToken(flow.Tokens), postLogout: "https://other-client.example/bye"));
        Assert.Equal(HttpStatusCode.BadRequest, withHint.StatusCode);
        Assert.Null(withHint.Headers.Location);

        // Without client_id or id_token_hint, the URI is not tied to a client, so it is refused even though one registered it.
        using var anon = host.Client();
        var unbound = await anon.GetAsync(Logout(null, postLogout: "https://other-client.example/bye"));
        Assert.Equal(HttpStatusCode.BadRequest, unbound.StatusCode);
        Assert.Null(unbound.Headers.Location);
        Assert.True(await SignedInAsync(user));
    }

    [Fact]
    public async Task Logout_without_a_hint_for_the_signed_in_user_is_refused_without_a_logout_page()
    {
        await using var host = await StartOidcAsync();
        var (user, _) = await host.UserAsync("nohint");
        var flow = await host.SignInAsync(user);
        var (other, _) = await host.UserAsync("other");
        var others = await host.SignInAsync(other);

        var noHint = await user.GetAsync(Logout(null, clientId: flow.Client.ClientId, postLogout: PostLogout));
        Assert.Equal(HttpStatusCode.BadRequest, noHint.StatusCode);
        Assert.Null(noHint.Headers.Location);

        // An ID token of another user (an attacker's own, say) does not sign this user out.
        var wrongUser = await user.GetAsync(Logout(IdToken(others.Tokens), postLogout: PostLogout));
        Assert.Equal(HttpStatusCode.BadRequest, wrongUser.StatusCode);
        Assert.True(await SignedInAsync(user));
    }

    [Fact]
    public async Task Logout_without_a_hint_goes_to_the_logout_page_which_returns_to_logout_after_signing_out()
    {
        await using var host = await StartOidcAsync(configure: options => options.LogoutUrl = SignOutPage);
        var (user, _) = await host.UserAsync("confirm");
        var flow = await host.SignInAsync(user);

        var response = await user.GetAsync(Logout(null, clientId: flow.Client.ClientId, postLogout: PostLogout, state: "s1"));
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(SignOutPage + "?returnUrl=", location, StringComparison.Ordinal);
        var returnUrl = Query(location)["returnUrl"];
        Assert.StartsWith("/connect/logout?", returnUrl, StringComparison.Ordinal);
        Assert.True(await SignedInAsync(user));

        // The host page signs the user out, then sends the browser back.
        Assert.Equal(HttpStatusCode.NoContent, (await user.PostAsync("/test/signout", null)).StatusCode);
        var back = await user.GetAsync(returnUrl);
        Assert.StartsWith(PostLogout, back.Headers.Location?.ToString() ?? "", StringComparison.Ordinal);
        Assert.Equal("s1", Query(back.Headers.Location!.ToString())["state"]);
    }

    [Fact]
    public async Task A_signed_out_browser_with_client_id_is_sent_to_the_registered_uri()
    {
        await using var host = await StartOidcAsync();
        var client = await host.RegisterOidcClientAsync();
        using var anon = host.Client();

        var response = await anon.GetAsync(Logout(null, clientId: client.ClientId, postLogout: PostLogout));
        Assert.StartsWith(PostLogout, response.Headers.Location?.ToString() ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_seeded_client_and_a_developer_app_can_use_their_post_logout_uris()
    {
        await using var host = await StartOidcAsync(
            configure: options => options.Clients.Single(client => client.ClientId == SeededClientId).PostLogoutRedirectUris.Add("https://spa.example/bye"));
        var (user, _) = await host.UserAsync("seeded");
        using var anon = host.Client();
        Assert.StartsWith("https://spa.example/bye", (await anon.GetAsync(Logout(null, clientId: SeededClientId, postLogout: "https://spa.example/bye")))
            .Headers.Location?.ToString() ?? "", StringComparison.Ordinal);

        var created = await CreateAppAsync(user, ["https://dev.example/bye"]);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var app = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("app");
        Assert.Equal(["https://dev.example/bye"], Strings(app, "postLogoutRedirectUris"));
        Assert.StartsWith(
            "https://dev.example/bye",
            (await anon.GetAsync(Logout(null, clientId: app.GetProperty("clientId").GetString(), postLogout: "https://dev.example/bye")))
                .Headers.Location?.ToString() ?? "",
            StringComparison.Ordinal);

        var invalid = await CreateAppAsync(user, ["javascript:alert(1)"]);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.Contains("postLogoutRedirectUris", await invalid.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Dynamic_registration_validates_and_returns_post_logout_uris()
    {
        await using var host = await StartOidcAsync();
        using var anon = host.Client(cookies: false);

        var bad = await anon.PostAsJsonAsync("/connect/register", new
        {
            redirect_uris = new[] { Loopback },
            post_logout_redirect_uris = new[] { "http://evil.example/" },
            token_endpoint_auth_method = "none",
        });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Equal("invalid_client_metadata", (await bad.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());

        var good = await anon.PostAsJsonAsync("/connect/register", new
        {
            redirect_uris = new[] { Loopback },
            post_logout_redirect_uris = new[] { PostLogout },
            token_endpoint_auth_method = "none",
        });
        Assert.Equal(HttpStatusCode.Created, good.StatusCode);
        Assert.Equal([PostLogout], Strings(await good.Content.ReadFromJsonAsync<JsonElement>(), "post_logout_redirect_uris"));
    }

    [Fact]
    public async Task Changing_a_developer_apps_post_logout_uris_sends_it_back_to_review_and_edits_add_oidc_permissions()
    {
        await using var host = await StartOidcAsync(configure: options => options.DeveloperApps.RequireApproval = true);
        var (_, userId) = await host.UserAsync("review");
        await using var scope = host.Services.CreateAsyncScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOAuthDeveloperAppService>();
        var input = new OAuthDeveloperAppInput("Reviewed", "https://dev.example", null, ["https://dev.example/callback"])
        {
            PostLogoutRedirectUris = ["https://dev.example/bye"],
        };
        var created = await apps.CreateAsync(userId, input, confidential: false);
        var id = created.App!.Id;
        Assert.True(await apps.SetStatusAsync(id, OAuthDeveloperAppStatus.Active));

        // Leaving the list out keeps it, and needs no new review.
        var kept = await apps.UpdateAsync(id, userId, input with { Description = "Now with a description", PostLogoutRedirectUris = null });
        Assert.Equal(["https://dev.example/bye"], kept.App!.PostLogoutRedirectUris);
        Assert.Equal(OAuthDeveloperAppStatus.Active, kept.App.Status);

        var changed = await apps.UpdateAsync(id, userId, input with { PostLogoutRedirectUris = ["https://evil.example/bye"] });
        Assert.Equal(OAuthDeveloperAppStatus.PendingApproval, changed.App!.Status);

        var applications = scope.ServiceProvider.GetRequiredService<global::OpenIddict.Abstractions.IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(created.App.ClientId);
        var permissions = await applications.GetPermissionsAsync(application!);
        Assert.Contains("scp:openid", permissions);
        Assert.Contains("ept:end_session", permissions);
    }

    private static async Task<HttpResponseMessage> CreateAppAsync(HttpClient user, string[] postLogout)
    {
        var csrf = await user.GetFromJsonAsync<JsonElement>("/test/csrf");
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth/apps")
        {
            Content = JsonContent.Create(new
            {
                name = "Dev app",
                homepageUrl = "https://dev.example",
                redirectUris = new[] { "https://dev.example/callback" },
                postLogoutRedirectUris = postLogout,
            }),
        };
        request.Headers.Add(CsrfHeader, csrf.GetProperty("token").GetString());
        return await user.SendAsync(request);
    }

    internal static string Logout(string? idTokenHint, string? clientId = null, string? postLogout = null, string? state = null)
    {
        var query = new Dictionary<string, string?>();
        if (idTokenHint is not null)
        {
            query["id_token_hint"] = idTokenHint;
        }

        if (clientId is not null)
        {
            query["client_id"] = clientId;
        }

        if (postLogout is not null)
        {
            query["post_logout_redirect_uri"] = postLogout;
        }

        if (state is not null)
        {
            query["state"] = state;
        }

        return QueryHelpers.AddQueryString("/connect/logout", query);
    }

    internal static async Task<bool> SignedInAsync(HttpClient browser)
        => (await browser.GetFromJsonAsync<JsonElement>("/test/cookie-claims")).GetArrayLength() > 0;
}

/// <summary>The ID token <c>amr</c> reflects how the browser signed in.</summary>
public sealed class OAuthAuthenticationMethodTests
{
    [Theory]
    [InlineData(SignInMethod.Password, false, new[] { "pwd" })]
    [InlineData(SignInMethod.Password, true, new[] { "pwd", "otp", "mfa" })]
    [InlineData(SignInMethod.Passkey, false, new[] { "pop" })]
    [InlineData(SignInMethod.External, false, new[] { "fed" })]
    [InlineData(SignInMethod.EmailCode, false, new[] { "otp" })]
    public async Task Amr_follows_the_AuthEndpoints_sign_in_method(SignInMethod method, bool twoFactor, string[] expected)
    {
        await using var host = await StartOidcAsync(signInCompleters: true);
        using var browser = host.Client();
        var signIn = await browser.PostAsync($"/test/complete?email=amr-{Guid.NewGuid():N}@example.test&method={method}&twoFactor={twoFactor}", null);
        Assert.True(signIn.IsSuccessStatusCode || signIn.StatusCode == HttpStatusCode.Redirect, $"{(int)signIn.StatusCode}");

        var flow = await host.SignInAsync(browser);
        Assert.Equal(expected, Strings(Payload(IdToken(flow.Tokens)), "amr"));
    }

    [Fact]
    public async Task Amr_is_mfa_after_Identity_two_factor_sign_in()
    {
        await using var host = await StartOidcAsync();
        using var browser = host.Client();
        await browser.PostAsync($"/test/2fa/start?email=tfa-{Guid.NewGuid():N}@example.test", null);
        Assert.Equal(HttpStatusCode.NoContent, (await browser.PostAsync("/test/2fa/finish", null)).StatusCode);

        var flow = await host.SignInAsync(browser);
        Assert.Equal(["pwd", "otp", "mfa"], Strings(Payload(IdToken(flow.Tokens)), "amr"));
    }

    [Fact]
    public async Task Amr_is_left_out_when_the_cookie_does_not_say_how_the_user_signed_in()
    {
        await using var host = await StartOidcAsync();
        var (user, _) = await host.UserAsync("unknown");

        var flow = await host.SignInAsync(user);
        Assert.False(Payload(IdToken(flow.Tokens)).TryGetProperty("amr", out _));
    }

    [Fact]
    public async Task Amr_survives_the_security_stamp_check_that_rebuilds_the_cookie()
    {
        await using var host = await StartOidcAsync(
            signInCompleters: true,
            services: services => services.Configure<SecurityStampValidatorOptions>(options => options.ValidationInterval = TimeSpan.Zero));
        using var browser = host.Client();
        await browser.PostAsync($"/test/complete?email=stamp-{Guid.NewGuid():N}@example.test&method={SignInMethod.Passkey}", null);

        // Each request now revalidates the stamp and reissues the cookie from a fresh principal.
        await browser.GetAsync("/test/cookie-claims");
        var claims = await browser.GetFromJsonAsync<string[][]>("/test/cookie-claims");
        Assert.Contains(claims!, claim => claim[0] == "amr" && claim[1] == "pop");

        var flow = await host.SignInAsync(browser);
        Assert.Equal(["pop"], Strings(Payload(IdToken(flow.Tokens)), "amr"));
    }

    [Fact]
    public async Task Without_openid_the_cookie_gets_no_amr_from_this_package()
    {
        await using var host = await OAuthTestHost.StartAsync(signInCompleters: true);
        using var browser = host.Client();
        await browser.PostAsync($"/test/complete?email=plain-{Guid.NewGuid():N}@example.test&method={SignInMethod.Passkey}", null);

        var claims = await browser.GetFromJsonAsync<string[][]>("/test/cookie-claims");
        Assert.NotEmpty(claims!);
        Assert.DoesNotContain(claims!, claim => claim[0] == "amr");
    }
}

/// <summary>The default recipe maps the OpenID Connect routes too.</summary>
public sealed class OAuthOpenIdConnectRecipeTests
{
    [Fact]
    public async Task MapOAuthServer_serves_discovery_userinfo_and_logout_with_openid()
    {
        await using var host = await OAuthTestHost.StartAsync(options => options.Scopes.Add("openid"), recipe: true);
        var (user, userId) = await host.UserAsync("recipe");
        var flow = await host.SignInAsync(user, scope: "openid api");

        using var anon = host.Client(cookies: false);
        Assert.Equal(HttpStatusCode.OK, (await anon.GetAsync("/.well-known/openid-configuration")).StatusCode);
        Assert.Equal(userId, (await UserInfoAsync(host, flow.Tokens.AccessToken)).GetProperty("sub").GetString());
        Assert.StartsWith(PostLogout, (await user.GetAsync(OAuthLogoutTests.Logout(IdToken(flow.Tokens), postLogout: PostLogout)))
            .Headers.Location?.ToString() ?? "", StringComparison.Ordinal);
    }
}

/// <summary>A host without the <c>openid</c> scope behaves as before OpenID Connect support.</summary>
public sealed class OAuthWithoutOpenIdTests
{
    [Fact]
    public async Task No_oidc_routes_or_id_tokens_without_the_openid_scope()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (user, _) = await host.UserAsync("plainhost");
        var (_, tokens) = await host.IssueAsync(user);
        Assert.False(tokens.Body.TryGetProperty("id_token", out _));

        using var anon = host.Client(cookies: false);
        foreach (var path in new[] { "/.well-known/openid-configuration", "/connect/userinfo", "/connect/logout" })
        {
            Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync(path)).StatusCode);
        }

        var metadata = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-authorization-server");
        Assert.False(metadata.TryGetProperty("userinfo_endpoint", out _));
        Assert.False(metadata.TryGetProperty("end_session_endpoint", out _));
        Assert.DoesNotContain("openid", Strings(metadata, "scopes_supported"));
    }
}
