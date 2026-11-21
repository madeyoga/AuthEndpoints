using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>Telling people and agents apart: the caller kind, <c>act</c>, <c>RequireDirectPerson</c>, and the any-caller scheme.</summary>
public sealed class OAuthCallerKindTests
{
    private const string ApiKeyScheme = "TestApiKey";
    private const string ApiKeyPrefix = "ak_";

    [Fact]
    public async Task An_access_token_is_a_delegated_caller_with_the_acting_client()
    {
        await using var host = await StartCallerHostAsync();
        var (user, _) = await host.UserAsync("delegated");
        var (client, tokens) = await host.IssueAsync(user);

        var caller = await CallerAsync(host, "/test/caller/token", bearer: tokens.AccessToken);
        Assert.Equal(CallerKinds.Delegated, caller.GetProperty("kind").GetString());
        Assert.Equal(client.ClientId, caller.GetProperty("actor").GetString());
        Assert.False(caller.GetProperty("person").GetBoolean());
        Assert.Contains(CallerKinds.ClaimType, Strings(caller, "claims"));
        Assert.Contains(CallerKinds.ActorClaimType, Strings(caller, "claims"));
    }

    [Fact]
    public async Task The_cookie_is_a_person_without_a_stored_claim()
    {
        await using var host = await StartCallerHostAsync();
        var (user, _) = await host.UserAsync("person");

        var response = await user.GetAsync("/test/caller/cookie");
        var caller = JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());
        Assert.Equal(CallerKinds.Person, caller.GetProperty("kind").GetString());
        Assert.True(caller.GetProperty("person").GetBoolean());
        Assert.Equal(JsonValueKind.Null, caller.GetProperty("actor").ValueKind);
    }

    [Fact]
    public async Task RequireDirectPerson_allows_the_cookie_and_refuses_a_token_with_403()
    {
        await using var host = await StartCallerHostAsync();
        var (user, _) = await host.UserAsync("direct");
        var (_, tokens) = await host.IssueAsync(user);

        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/test/person-only")).StatusCode);

        using var api = host.Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await api.GetAsync("/test/person-only")).StatusCode);

        // The person's cookie sent along with the token does not make the token a person.
        using var both = new HttpRequestMessage(HttpMethod.Get, "/test/person-only");
        both.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await user.SendAsync(both)).StatusCode);
    }

    [Fact]
    public async Task The_any_caller_scheme_sends_each_credential_to_exactly_one_handler()
    {
        await using var host = await StartCallerHostAsync();
        var (user, _) = await host.UserAsync("any");
        var (client, tokens) = await host.IssueAsync(user);

        // No Authorization header: the cookie.
        var cookie = JsonSerializer.Deserialize<JsonElement>(await (await user.GetAsync("/test/caller/any")).Content.ReadAsStringAsync());
        Assert.Equal(CallerKinds.Person, cookie.GetProperty("kind").GetString());

        // A bearer token: OAuth validation.
        var token = await CallerAsync(host, "/test/caller/any", bearer: tokens.AccessToken);
        Assert.Equal(CallerKinds.Delegated, token.GetProperty("kind").GetString());
        Assert.Equal(client.ClientId, token.GetProperty("actor").GetString());

        // An API key: the API key scheme.
        var key = await CallerAsync(host, "/test/caller/any", bearer: ApiKeyPrefix + "valid");
        Assert.Equal(CallerKinds.ApiKey, key.GetProperty("kind").GetString());

        // A bad token with a valid cookie is 401: the cookie is never read for it.
        using var bad = new HttpRequestMessage(HttpMethod.Get, "/test/caller/any");
        bad.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-token");
        Assert.Equal(HttpStatusCode.Unauthorized, (await user.SendAsync(bad)).StatusCode);

        // So is a bad API key.
        using var badKey = new HttpRequestMessage(HttpMethod.Get, "/test/caller/any");
        badKey.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ApiKeyPrefix + "wrong");
        Assert.Equal(HttpStatusCode.Unauthorized, (await user.SendAsync(badKey)).StatusCode);
    }

    [Fact]
    public async Task Person_only_routes_through_the_any_caller_scheme_refuse_tokens_and_api_keys()
    {
        await using var host = await StartCallerHostAsync();
        var (user, _) = await host.UserAsync("refuse");
        var (_, tokens) = await host.IssueAsync(user);

        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/test/person-only/any")).StatusCode);
        foreach (var credential in new[] { tokens.AccessToken, ApiKeyPrefix + "valid" })
        {
            using var api = host.Client(cookies: false);
            api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", credential);
            Assert.Equal(HttpStatusCode.Forbidden, (await api.GetAsync("/test/person-only/any")).StatusCode);
        }
    }

    [Fact]
    public async Task Consent_and_connected_apps_refuse_a_token_that_a_host_scheme_forwards()
    {
        // The host points the OAuth server's AuthenticationScheme at the any-caller scheme, so a token reaches these routes.
        await using var host = await StartCallerHostAsync(options => options.AuthenticationScheme = AnyCallerAuthenticationBuilderExtensions.SchemeName);
        var (user, _) = await host.UserAsync("forwarded");
        var (_, tokens) = await host.IssueAsync(user);

        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/oauth/authorizations")).StatusCode);
        foreach (var credential in new[] { tokens.AccessToken, ApiKeyPrefix + "valid" })
        {
            using var api = host.Client(cookies: false);
            api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", credential);
            Assert.Equal(HttpStatusCode.Forbidden, (await api.GetAsync("/oauth/authorizations")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await api.GetAsync($"/oauth/requests/{Guid.NewGuid()}")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await api.GetAsync("/oauth/apps")).StatusCode);
        }
    }

    [Fact]
    public void The_any_caller_scheme_needs_both_api_key_settings_or_neither()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentException>(() => services.AddAuthentication().AddAnyCallerScheme(options => options.ApiKeyPrefix = "ak_"));
        Assert.Throws<ArgumentException>(() => services.AddAuthentication().AddAnyCallerScheme(options => options.ApiKeyScheme = "Keys"));
    }

    private static Task<OAuthTestHost> StartCallerHostAsync(Action<OAuthServerOptions>? configure = null)
        => StartAsync(
            configure,
            services: services =>
            {
                services.AddAuthentication()
                    .AddScheme<AuthenticationSchemeOptions, TestApiKeyHandler>(ApiKeyScheme, null)
                    .AddAnyCallerScheme(options =>
                    {
                        options.BearerScheme = OAuthServerServiceCollectionExtensions.ValidationScheme;
                        options.ApiKeyScheme = ApiKeyScheme;
                        options.ApiKeyPrefix = ApiKeyPrefix;
                    });
                services.AddAuthorization(options =>
                {
                    options.AddPolicy("token", policy => policy
                        .AddAuthenticationSchemes(OAuthServerServiceCollectionExtensions.ValidationScheme)
                        .RequireAuthenticatedUser());
                    options.AddPolicy("cookie", policy => policy
                        .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme)
                        .RequireAuthenticatedUser());
                    options.AddPolicy("any", policy => policy
                        .AddAuthenticationSchemes(AnyCallerAuthenticationBuilderExtensions.SchemeName)
                        .RequireAuthenticatedUser());
                    options.AddPolicy("person", policy => policy
                        .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, OAuthServerServiceCollectionExtensions.ValidationScheme)
                        .RequireDirectPerson());
                });
            },
            map: app =>
            {
                foreach (var policy in new[] { "token", "cookie", "any" })
                {
                    app.MapGet($"/test/caller/{policy}", (ClaimsPrincipal user) => Results.Ok(new
                    {
                        kind = user.GetCallerKind(),
                        actor = user.GetActingClientId(),
                        person = user.IsDirectPerson(),
                        claims = user.Claims.Select(claim => claim.Type).Distinct().ToArray(),
                    })).RequireAuthorization(policy);
                }

                app.MapGet("/test/person-only", () => Results.Ok()).RequireAuthorization("person");
                app.MapGet("/test/person-only/any", () => Results.Ok())
                    .RequireAuthorization("any")
                    .RequireDirectPerson();
            });

    private static async Task<JsonElement> CallerAsync(OAuthTestHost host, string path, string bearer)
    {
        using var api = host.Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        var response = await api.GetAsync(path);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode} {text}");
        return JsonSerializer.Deserialize<JsonElement>(text);
    }

    private static string[] Strings(JsonElement element, string name)
        => element.GetProperty(name).EnumerateArray().Select(item => item.GetString()!).ToArray();

    /// <summary>Stands in for an API key scheme (#422): <c>ak_valid</c> is the only key, and it marks itself as an API key.</summary>
    private sealed class TestApiKeyHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var header = Request.Headers.Authorization.ToString();
            if (!header.StartsWith("Bearer " + ApiKeyPrefix, StringComparison.Ordinal))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            if (header != "Bearer " + ApiKeyPrefix + "valid")
            {
                return Task.FromResult(AuthenticateResult.Fail("Unknown API key."));
            }

            var identity = new ClaimsIdentity(
                [new Claim(ClaimTypes.NameIdentifier, "key-owner"), new Claim(CallerKinds.ClaimType, CallerKinds.ApiKey)],
                Scheme.Name);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
        }
    }
}
