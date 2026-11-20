using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary><c>RequireOAuthScope</c>, <c>RequireOAuthScopeWhenDelegated</c>, and the <see cref="ClaimsPrincipal"/> scope helpers.</summary>
public sealed class OAuthScopeAuthorizationTests
{
    [Fact]
    public async Task RequireOAuthScope_needs_every_listed_scope()
    {
        await using var host = await StartScopesAsync();
        var (user, _) = await host.UserAsync("scope-token");
        var both = await IssueAsync(host, user, "api profile");
        var apiOnly = await IssueAsync(host, user, "api");

        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, "/scoped", both)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, "/scoped", apiOnly)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, "/scoped-api", apiOnly)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CallAsync(host, "/scoped", null)).StatusCode);
    }

    [Fact]
    public async Task RequireOAuthScope_does_not_accept_the_cookie()
    {
        await using var host = await StartScopesAsync();
        var (user, _) = await host.UserAsync("scope-cookie-only");

        Assert.Equal(HttpStatusCode.Unauthorized, (await user.GetAsync("/scoped")).StatusCode);
    }

    [Fact]
    public async Task WhenDelegated_lets_cookie_users_through_and_checks_tokens()
    {
        await using var host = await StartScopesAsync();
        var (user, _) = await host.UserAsync("scope-shared");
        var withProfile = await IssueAsync(host, user, "api profile");
        var withoutProfile = await IssueAsync(host, user, "api");

        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/shared")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, "/shared", withProfile)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, "/shared", withoutProfile)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CallAsync(host, "/shared", null)).StatusCode);
    }

    [Fact]
    public async Task WhenDelegated_still_checks_the_token_when_the_request_also_has_a_cookie()
    {
        await using var host = await StartScopesAsync();
        var (user, _) = await host.UserAsync("scope-both");
        var withoutProfile = await IssueAsync(host, user, "api");

        using var request = new HttpRequestMessage(HttpMethod.Get, "/shared");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", withoutProfile);
        Assert.Equal(HttpStatusCode.Forbidden, (await user.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task WhenDelegated_keeps_the_route_role_check_for_cookie_users()
    {
        await using var host = await StartScopesAsync();
        var (user, userId) = await host.UserAsync("scope-role");

        // Refused by the role check. The status comes from the schemes' forbid handlers, not from the scope requirement.
        Assert.NotEqual(HttpStatusCode.OK, (await user.GetAsync("/shared-admin")).StatusCode);
        await AddRoleAsync(host, userId, "admin");
        var again = await SignInAgainAsync(host, userId);
        Assert.Equal(HttpStatusCode.OK, (await again.GetAsync("/shared-admin")).StatusCode);
    }

    [Fact]
    public async Task Principal_helpers_read_only_the_token_identity()
    {
        await using var host = await StartScopesAsync();
        var (user, _) = await host.UserAsync("scope-helpers");
        var token = await IssueAsync(host, user, "api profile");

        var cookie = await user.GetFromJsonAsync<JsonElement>("/caller");
        Assert.False(cookie.GetProperty("delegated").GetBoolean());
        Assert.Empty(cookie.GetProperty("scopes").EnumerateArray());
        Assert.False(cookie.GetProperty("hasProfile").GetBoolean());

        var response = await CallAsync(host, "/caller", token);
        var delegated = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(delegated.GetProperty("delegated").GetBoolean());
        Assert.Equal(["api", "offline_access", "profile"], delegated.GetProperty("scopes").EnumerateArray().Select(item => item.GetString()).Order());
        Assert.True(delegated.GetProperty("hasProfile").GetBoolean());
    }

    [Fact]
    public void Scope_claims_on_an_identity_that_is_not_an_access_token_do_not_count()
    {
        var identity = new ClaimsIdentity(
            [new Claim(OpenIddictConstants.Claims.Private.Scope, "api"), new Claim(ClaimTypes.NameIdentifier, "1")],
            "Identity.Application");
        var principal = new ClaimsPrincipal(identity);

        Assert.False(principal.IsOAuthDelegated());
        Assert.Empty(principal.GetOAuthScopes());
        Assert.False(principal.HasOAuthScope("api"));
    }

    [Fact]
    public async Task Every_access_token_identity_needs_every_scope()
    {
        var requirement = new OAuthScopeRequirement(["api"]);
        var principal = new ClaimsPrincipal([AccessTokenIdentity("api"), AccessTokenIdentity("profile")]);
        var context = new AuthorizationHandlerContext([requirement], principal, null);

        await requirement.HandleAsync(context);

        Assert.False(context.HasSucceeded);
        Assert.False(principal.HasOAuthScope("api"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(" ")]
    public void A_requirement_needs_real_scopes(string? scope)
    {
        string[] scopes = scope is null ? [] : [scope];
        Assert.ThrowsAny<ArgumentException>(() => new AuthorizationPolicyBuilder().RequireOAuthScope(scopes));
        Assert.ThrowsAny<ArgumentException>(() => new AuthorizationPolicyBuilder().RequireOAuthScopeWhenDelegated(scopes));
    }

    [Fact]
    public void RequireOAuthScope_uses_the_validation_scheme()
    {
        var policy = new AuthorizationPolicyBuilder().RequireOAuthScope("api").Build();
        Assert.Equal([OAuthServerServiceCollectionExtensions.ValidationScheme], policy.AuthenticationSchemes);
        var requirement = Assert.Single(policy.Requirements.OfType<OAuthScopeRequirement>());
        Assert.Equal(["api"], requirement.Scopes);
        Assert.False(requirement.OnlyWhenDelegated);

        var shared = new AuthorizationPolicyBuilder().RequireOAuthScopeWhenDelegated("api").Build();
        Assert.Empty(shared.AuthenticationSchemes);
        Assert.True(Assert.Single(shared.Requirements.OfType<OAuthScopeRequirement>()).OnlyWhenDelegated);
    }

    private static ClaimsIdentity AccessTokenIdentity(string scope)
    {
        var identity = new ClaimsIdentity("Bearer");
        identity.SetTokenType(OpenIddictConstants.TokenTypeIdentifiers.AccessToken);
        identity.SetScopes(scope);
        return identity;
    }

    private static Task<OAuthTestHost> StartScopesAsync() => StartAsync(
        services: services => services.Configure<AuthorizationOptions>(options =>
        {
            options.AddPolicy("scoped", policy => policy.RequireOAuthScope("api", "profile"));
            options.AddPolicy("scoped-api", policy => policy.RequireOAuthScope("api"));
            options.AddPolicy("shared", policy => policy
                .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, OAuthServerServiceCollectionExtensions.ValidationScheme)
                .RequireAuthenticatedUser()
                .RequireOAuthScopeWhenDelegated("profile"));
            options.AddPolicy("shared-admin", policy => policy
                .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, OAuthServerServiceCollectionExtensions.ValidationScheme)
                .RequireRole("admin")
                .RequireOAuthScopeWhenDelegated("profile"));
        }),
        map: app =>
        {
            app.MapGet("/scoped", () => Results.Ok()).RequireAuthorization("scoped");
            app.MapGet("/scoped-api", () => Results.Ok()).RequireAuthorization("scoped-api");
            app.MapGet("/shared", () => Results.Ok()).RequireAuthorization("shared");
            app.MapGet("/shared-admin", () => Results.Ok()).RequireAuthorization("shared-admin");
            app.MapGet("/caller", (ClaimsPrincipal principal) => Results.Ok(new
            {
                delegated = principal.IsOAuthDelegated(),
                scopes = principal.GetOAuthScopes(),
                hasProfile = principal.HasOAuthScope("profile"),
            })).RequireAuthorization("shared");
        });

    private static async Task<string> IssueAsync(OAuthTestHost host, HttpClient user, string scope)
    {
        var client = await host.RegisterAsync(name: "Scoped", scope: "api profile");
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge, scope: scope);
        var approved = await ApproveAsync(user, id);
        using var anon = host.Client(cookies: false);
        return (await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, approved["code"], pkce.Verifier)))).AccessToken;
    }

    private static async Task<HttpResponseMessage> CallAsync(OAuthTestHost host, string path, string? accessToken)
    {
        using var api = host.Client(cookies: false);
        if (accessToken is not null)
        {
            api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        return await api.GetAsync(path);
    }

    private static async Task AddRoleAsync(OAuthTestHost host, string userId, string role)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        Assert.True((await roles.CreateAsync(new IdentityRole(role))).Succeeded);
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        Assert.True((await users.AddToRoleAsync((await users.FindByIdAsync(userId))!, role)).Succeeded);
    }

    /// <summary>A fresh cookie, so it carries the roles added after the first sign-in.</summary>
    private static async Task<HttpClient> SignInAgainAsync(OAuthTestHost host, string userId)
    {
        string email;
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            email = (await users.FindByIdAsync(userId))!.Email!;
        }

        var client = host.Client();
        (await client.PostAsync($"/test/signin?email={Uri.EscapeDataString(email)}", null)).EnsureSuccessStatusCode();
        return client;
    }
}
