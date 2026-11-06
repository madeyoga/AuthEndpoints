using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>OpenID Connect hosts: ID tokens, userinfo, logout, and discovery.</summary>
public sealed class OAuthOpenIdConnectTests
{
    internal const string PostLogout = "http://127.0.0.1:9/signed-out";

    [Fact]
    public async Task Discovery_uses_the_configured_issuer_and_lists_the_oidc_endpoints()
    {
        await using var host = await StartOidcAsync();
        using var anon = host.Client(baseAddress: "https://evil.example/", cookies: false);

        foreach (var path in new[] { ".well-known/openid-configuration", ".well-known/oauth-authorization-server" })
        {
            var metadata = await anon.GetFromJsonAsync<JsonElement>(path);
            Assert.Equal(Issuer, metadata.GetProperty("issuer").GetString());
            Assert.Equal(Issuer + "connect/userinfo", metadata.GetProperty("userinfo_endpoint").GetString());
            Assert.Equal(Issuer + "connect/logout", metadata.GetProperty("end_session_endpoint").GetString());
            Assert.Equal(Issuer + ".well-known/jwks", metadata.GetProperty("jwks_uri").GetString());
            Assert.Equal(Issuer + "connect/authorize", metadata.GetProperty("authorization_endpoint").GetString());
            Assert.Contains("openid", Strings(metadata, "scopes_supported"));
            Assert.Contains("email", Strings(metadata, "scopes_supported"));
            Assert.Equal(["code"], Strings(metadata, "response_types_supported"));
            Assert.Contains("public", Strings(metadata, "subject_types_supported"));
            Assert.Contains("RS256", Strings(metadata, "id_token_signing_alg_values_supported"));
            foreach (var claim in new[] { "sub", "amr", "email", "email_verified" })
            {
                Assert.Contains(claim, Strings(metadata, "claims_supported"));
            }

            Assert.DoesNotContain("evil.example", metadata.GetRawText(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task The_id_token_has_the_issuer_client_audience_subject_and_nonce_and_is_signed_with_the_published_keys()
    {
        await using var host = await StartOidcAsync();
        var (user, userId) = await host.UserAsync("idtoken");
        var flow = await host.SignInAsync(user, nonce: "n-0S6_WzA2Mj");

        var idToken = flow.Tokens.Body.GetProperty("id_token").GetString()!;
        using var anon = host.Client(cookies: false);
        var jwks = new JsonWebKeySet(await anon.GetStringAsync(".well-known/jwks"));
        var validated = await new JsonWebTokenHandler().ValidateTokenAsync(idToken, new TokenValidationParameters
        {
            ValidIssuer = Issuer,
            ValidAudience = flow.Client.ClientId,
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ClockSkew = TimeSpan.Zero,
        });
        Assert.True(validated.IsValid, validated.Exception?.Message);

        var payload = Payload(idToken);
        Assert.Equal(Issuer, payload.GetProperty("iss").GetString());
        Assert.Equal(flow.Client.ClientId, Audiences(payload).Single());
        Assert.Equal(flow.Client.ClientId, payload.GetProperty("azp").GetString());
        Assert.Equal(userId, payload.GetProperty("sub").GetString());
        Assert.Equal("n-0S6_WzA2Mj", payload.GetProperty("nonce").GetString());
        Assert.Equal(userId, await host.SubjectAsync(flow.Tokens.AccessToken));
        Assert.Contains("openid", flow.Tokens.Body.GetProperty("scope").GetString()!.Split(' '));
        foreach (var name in payload.EnumerateObject().Select(property => property.Name))
        {
            Assert.DoesNotContain("ae_", name, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Each_flow_returns_its_own_nonce_and_a_flow_without_one_gets_none()
    {
        await using var host = await StartOidcAsync();
        var (user, _) = await host.UserAsync("nonce");

        var first = await host.SignInAsync(user, nonce: "first-nonce");
        var second = await host.SignInAsync(user, nonce: "second-nonce");
        var none = await host.SignInAsync(user, nonce: null);

        Assert.Equal("first-nonce", Payload(IdToken(first.Tokens)).GetProperty("nonce").GetString());
        Assert.Equal("second-nonce", Payload(IdToken(second.Tokens)).GetProperty("nonce").GetString());
        Assert.False(Payload(IdToken(none.Tokens)).TryGetProperty("nonce", out _));
    }

    [Fact]
    public async Task Refresh_returns_a_new_id_token_for_the_same_subject_and_client()
    {
        await using var host = await StartOidcAsync();
        var (user, userId) = await host.UserAsync("refresh");
        var flow = await host.SignInAsync(user, nonce: "refresh-nonce");

        using var anon = host.Client(cookies: false);
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(flow.Client.ClientId, flow.Tokens.RefreshToken)));

        var payload = Payload(IdToken(refreshed));
        var original = Payload(IdToken(flow.Tokens));
        Assert.Equal(userId, payload.GetProperty("sub").GetString());
        Assert.Equal(original.GetProperty("email").GetString(), payload.GetProperty("email").GetString());
        Assert.Equal(original.GetProperty("email_verified").ValueKind, payload.GetProperty("email_verified").ValueKind);
        Assert.Equal(flow.Client.ClientId, Audiences(payload).Single());
        Assert.Equal(Issuer, payload.GetProperty("iss").GetString());
    }

    [Fact]
    public async Task Without_openid_in_the_request_there_is_no_id_token()
    {
        await using var host = await StartOidcAsync();
        var (user, _) = await host.UserAsync("plain");
        var flow = await host.SignInAsync(user, scope: "api");

        Assert.False(flow.Tokens.Body.TryGetProperty("id_token", out _));
    }

    [Fact]
    public async Task Id_token_claims_never_reach_the_access_token_and_the_api_refuses_an_id_token()
    {
        await using var host = await StartOidcAsync();
        var (user, _) = await host.UserAsync("split");
        var flow = await host.SignInAsync(user);

        var response = await host.CallApiAsync(flow.Tokens.AccessToken);
        var types = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("claims").EnumerateArray()
            .Select(item => item.GetString()).ToArray();
        foreach (var type in new[] { "email", "email_verified", "amr", "nonce", OAuthServerConstants.UserIdClaim, OAuthServerConstants.UserStampClaim })
        {
            Assert.DoesNotContain(type, types);
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.CallApiAsync(IdToken(flow.Tokens))).StatusCode);
    }

    [Fact]
    public async Task The_id_token_subject_comes_from_a_custom_principal_factory_and_the_user_email_is_not_attached_to_it()
    {
        await using var host = await StartOidcAsync(server: server => server.AddPrincipalFactory<AgentFactory>());
        var (user, userId) = await host.UserAsync("agent");
        var flow = await host.SignInAsync(user);

        var payload = Payload(IdToken(flow.Tokens));
        Assert.Equal("agent-" + userId, payload.GetProperty("sub").GetString());
        Assert.Equal("agent-" + userId, await host.SubjectAsync(flow.Tokens.AccessToken));
        Assert.False(payload.TryGetProperty("email", out _));

        var info = await UserInfoAsync(host, flow.Tokens.AccessToken);
        Assert.Equal("agent-" + userId, info.GetProperty("sub").GetString());
        Assert.False(info.TryGetProperty("email", out _));
    }

    [Fact]
    public async Task Email_claims_need_the_email_scope_and_email_verified_follows_EmailConfirmed()
    {
        await using var host = await StartOidcAsync();
        var (user, userId) = await host.UserAsync("verified");
        await ChangeUserAsync(host, userId, (users, u) =>
        {
            u.EmailConfirmed = false;
            return users.UpdateAsync(u);
        });

        var withEmail = await host.SignInAsync(user, scope: "openid email api");
        var payload = Payload(IdToken(withEmail.Tokens));
        var email = payload.GetProperty("email").GetString();
        Assert.StartsWith("verified-", email, StringComparison.Ordinal);
        Assert.Equal(JsonValueKind.False, payload.GetProperty("email_verified").ValueKind);
        var info = await UserInfoAsync(host, withEmail.Tokens.AccessToken);
        Assert.Equal(userId, info.GetProperty("sub").GetString());
        Assert.Equal(email, info.GetProperty("email").GetString());
        Assert.Equal(JsonValueKind.False, info.GetProperty("email_verified").ValueKind);

        // Userinfo reads the user on every call.
        await ChangeUserAsync(host, userId, (users, u) =>
        {
            u.EmailConfirmed = true;
            return users.UpdateAsync(u);
        });
        Assert.Equal(JsonValueKind.True, (await UserInfoAsync(host, withEmail.Tokens.AccessToken)).GetProperty("email_verified").ValueKind);
        Assert.Equal(
            JsonValueKind.True,
            Payload(IdToken((await host.SignInAsync(user, scope: "openid email api")).Tokens)).GetProperty("email_verified").ValueKind);

        var withoutEmail = await host.SignInAsync(user, scope: "openid api");
        Assert.False(Payload(IdToken(withoutEmail.Tokens)).TryGetProperty("email", out _));
        info = await UserInfoAsync(host, withoutEmail.Tokens.AccessToken);
        Assert.Equal(userId, info.GetProperty("sub").GetString());
        Assert.False(info.TryGetProperty("email", out _));
        Assert.False(info.TryGetProperty("email_verified", out _));
    }

    [Fact]
    public async Task Userinfo_rejects_a_token_without_openid_and_a_missing_token()
    {
        await using var host = await StartOidcAsync();
        var (user, userId) = await host.UserAsync("noopenid");
        var plain = await host.SignInAsync(user, scope: "api");

        using var api = host.Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", plain.Tokens.AccessToken);
        var forbidden = await api.GetAsync("/connect/userinfo");
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        Assert.Contains("insufficient_scope", forbidden.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);

        using var anon = host.Client(cookies: false);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/connect/userinfo")).StatusCode);

        var oidc = await host.SignInAsync(user);
        using var post = host.Client(cookies: false);
        post.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", oidc.Tokens.AccessToken);
        var posted = await post.PostAsync("/connect/userinfo", new FormUrlEncodedContent([]));
        Assert.Equal(HttpStatusCode.OK, posted.StatusCode);
        Assert.Equal(userId, (await posted.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("sub").GetString());
    }

    [Fact]
    public async Task Userinfo_rejects_the_token_of_a_deleted_user()
    {
        await using var host = await StartOidcAsync();
        var (user, userId) = await host.UserAsync("gone");
        var flow = await host.SignInAsync(user);

        await ChangeUserAsync(host, userId, (users, u) => users.DeleteAsync(u));

        using var api = host.Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", flow.Tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.GetAsync("/connect/userinfo")).StatusCode);
    }

    [Fact]
    public async Task Prompt_login_and_max_age_are_refused_instead_of_ignored()
    {
        await using var host = await StartOidcAsync();
        var (user, _) = await host.UserAsync("prompt");
        var client = await host.RegisterAsync("Prompt");

        foreach (var url in new[]
        {
            AuthorizeUrl(client.ClientId, client.RedirectUri, Pkce.Create().Challenge, scope: "openid api", prompt: "login"),
            AuthorizeUrl(client.ClientId, client.RedirectUri, Pkce.Create().Challenge, scope: "openid api", maxAge: "0"),
        })
        {
            var response = await user.GetAsync(url);
            var location = response.Headers.Location?.ToString() ?? "";
            Assert.StartsWith(client.RedirectUri, location, StringComparison.Ordinal);
            Assert.Equal("invalid_request", Query(location)["error"]);
        }
    }

    [Fact]
    public async Task A_client_defined_without_openid_cannot_request_it()
    {
        await using var host = await StartOidcAsync(configure: options =>
        {
            var client = new OAuthClientDefinition { ClientId = "api-only" };
            client.RedirectUris.Add(Loopback);
            client.Scopes.Add("api");
            options.Clients.Add(client);
        });
        var (user, _) = await host.UserAsync("apionly");

        var response = await user.GetAsync(AuthorizeUrl("api-only", Loopback, Pkce.Create().Challenge, scope: "openid api"));
        Assert.Equal("invalid_scope", Query(response.Headers.Location!.ToString())["error"]);
        Assert.StartsWith(ConsentUrl, (await user.GetAsync(AuthorizeUrl("api-only", Loopback, Pkce.Create().Challenge, scope: "api")))
            .Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    internal static Task<OAuthTestHost> StartOidcAsync(
        Action<OAuthServerOptions>? configure = null,
        Action<OAuthServerBuilder>? server = null,
        Action<IServiceCollection>? services = null,
        bool signInCompleters = false,
        Action<IServiceCollection>? beforeServer = null,
        Action<Microsoft.AspNetCore.Builder.WebApplication>? map = null)
        => OAuthTestHost.StartAsync(
            options =>
            {
                options.Scopes.Add("openid");
                options.Scopes.Add("email");
                configure?.Invoke(options);
            },
            services: services,
            server: server,
            signInCompleters: signInCompleters,
            beforeServer: beforeServer,
            map: map);

    internal static string IdToken(TokenPair tokens) => tokens.Body.GetProperty("id_token").GetString()!;

    internal static JsonElement Payload(string jwt)
    {
        var part = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        part = part.PadRight(part.Length + (4 - part.Length % 4) % 4, '=');
        return JsonSerializer.Deserialize<JsonElement>(Encoding.UTF8.GetString(Convert.FromBase64String(part)));
    }

    internal static string[] Audiences(JsonElement payload)
    {
        var aud = payload.GetProperty("aud");
        return aud.ValueKind == JsonValueKind.Array ? aud.EnumerateArray().Select(item => item.GetString()!).ToArray() : [aud.GetString()!];
    }

    internal static string[] Strings(JsonElement json, string property)
        => json.GetProperty(property).EnumerateArray().Select(item => item.GetString()!).ToArray();

    internal static async Task<JsonElement> UserInfoAsync(OAuthTestHost host, string accessToken)
    {
        using var api = host.Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await api.GetAsync("/connect/userinfo");
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode} {text} {response.Headers.WwwAuthenticate}");
        return JsonSerializer.Deserialize<JsonElement>(text);
    }

    internal static async Task ChangeUserAsync(
        OAuthTestHost host, string userId, Func<UserManager<IdentityUser>, IdentityUser, Task<IdentityResult>> change)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var user = await users.FindByIdAsync(userId);
        Assert.True((await change(users, user!)).Succeeded);
    }

    private sealed class AgentFactory : IOAuthPrincipalFactory
    {
        public ValueTask<ClaimsPrincipal?> CreateAsync(OAuthPrincipalContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult<ClaimsPrincipal?>(OAuthPrincipals.ForSubject("agent-" + context.UserId));
    }
}

internal sealed record OidcFlow(RegisteredClient Client, TokenPair Tokens);

internal static class OidcHostExtensions
{
    /// <summary>Registers a client, runs authorize, consent, and the code exchange, and returns the token response.</summary>
    public static async Task<OidcFlow> SignInAsync(
        this OAuthTestHost host,
        HttpClient user,
        string scope = "openid email api",
        string? nonce = "nonce-1",
        string? postLogoutRedirect = OAuthOpenIdConnectTests.PostLogout)
    {
        var client = await host.RegisterOidcClientAsync(postLogoutRedirect);
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge, scope: scope, nonce: nonce);
        var approved = await ApproveAsync(user, id);
        using var anon = host.Client(cookies: false);
        return new OidcFlow(client, await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, approved["code"], pkce.Verifier))));
    }

    public static async Task<RegisteredClient> RegisterOidcClientAsync(this OAuthTestHost host, string? postLogoutRedirect = OAuthOpenIdConnectTests.PostLogout)
    {
        using var anon = host.Client(cookies: false);
        var response = await anon.PostAsJsonAsync("/connect/register", new
        {
            redirect_uris = new[] { Loopback },
            post_logout_redirect_uris = postLogoutRedirect is null ? Array.Empty<string>() : [postLogoutRedirect],
            token_endpoint_auth_method = "none",
            client_name = "OIDC client",
        });
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.Created, text);
        return new RegisteredClient(JsonSerializer.Deserialize<JsonElement>(text).GetProperty("client_id").GetString()!, Loopback);
    }
}
