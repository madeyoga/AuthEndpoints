using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>
/// The setup of the "Expose an MCP server with per-user OAuth" guide, end to end: discovery, registration, consent,
/// a token for /mcp, role and scope checks, a shared /api route, a role change at refresh, and disconnecting.
/// </summary>
public sealed class OAuthMcpGuideTests
{
    private const string Mcp = "https://localhost/mcp";

    [Fact]
    public async Task An_assistant_connects_and_acts_as_the_person_within_the_granted_scopes()
    {
        await using var host = await StartAsync(Guide, Policies, Map);
        using var anon = host.Client(cookies: false);

        // 2. Discovery: the 401 on /mcp points at the /mcp document, which points at this server.
        var challenge = await anon.GetAsync("/mcp");
        Assert.Equal(HttpStatusCode.Unauthorized, challenge.StatusCode);
        Assert.Contains(
            "resource_metadata=\"https://localhost/.well-known/oauth-protected-resource/mcp\"",
            challenge.Headers.WwwAuthenticate.ToString(),
            StringComparison.Ordinal);
        var resource = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-protected-resource/mcp");
        Assert.Equal(Mcp, resource.GetProperty("resource").GetString());
        Assert.Equal(Issuer, resource.GetProperty("authorization_servers")[0].GetString());
        Assert.Equal(["mcp", "reports.read"], resource.GetProperty("scopes_supported").EnumerateArray().Select(item => item.GetString()!).ToArray());

        // 3. Registration: a client anyone can bring cannot hold the first-party scope.
        var account = await anon.PostAsJsonAsync("/connect/register", new { redirect_uris = new[] { Loopback }, scope = "account" });
        Assert.Equal(HttpStatusCode.BadRequest, account.StatusCode);
        var client = await host.RegisterAsync("Example Assistant", scope: "mcp reports.read");

        // 4–6. Sign-in, consent, and a token for /mcp.
        var (user, userId) = await host.UserAsync("person");
        await AddRoleAsync(host, userId, "Member");
        var tokens = await ConnectAsync(host, user, client, "mcp reports.read", Mcp);

        // 7. Calls run as the person, with their roles, within the granted scopes.
        var me = await CallAsync(host, tokens.AccessToken, "/mcp");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal(userId, (await me.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("userId").GetString());
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, tokens.AccessToken, "/mcp/reports")).StatusCode);
        // An /mcp token cannot use the shared /api route, even with the scope.
        var shared = await CallAsync(host, tokens.AccessToken, "/api/reports");
        Assert.Equal(HttpStatusCode.Forbidden, shared.StatusCode);
        Assert.Null(shared.Headers.Location);
        // The cookie user reaches the shared route as before.
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/api/reports")).StatusCode);

        // A grant without reports.read can use the server, but not the reports tool.
        var narrow = await ConnectAsync(host, user, client, "mcp", Mcp);
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, narrow.AccessToken, "/mcp")).StatusCode);
        var tool = await CallAsync(host, narrow.AccessToken, "/mcp/reports");
        Assert.Equal(HttpStatusCode.Forbidden, tool.StatusCode);
        Assert.Null(tool.Headers.Location);

        // A token for /api with the scope reaches the shared route, and not /mcp.
        var apiTokens = await ConnectAsync(host, user, client, "reports.read", Audience);
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, apiTokens.AccessToken, "/api/reports")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, apiTokens.AccessToken, "/mcp")).StatusCode);

        // A role change reaches the assistant at its next refresh.
        await RemoveRoleAsync(host, userId, "Member");
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, refreshed.AccessToken, "/mcp")).StatusCode);

        // 8. Disconnect: revoking the authorization ends the grant.
        await AddRoleAsync(host, userId, "Member");
        var again = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, refreshed.RefreshToken)));
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, again.AccessToken, "/mcp")).StatusCode);
        var authorizationId = await AuthorizationIdAsync(host, again.AccessToken);
        await using (var scope = host.Services.CreateAsyncScope())
        {
            Assert.True(await scope.ServiceProvider.GetRequiredService<IOAuthConsentService>().RevokeAuthorizationAsync(authorizationId));
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await CallAsync(host, again.AccessToken, "/mcp")).StatusCode);
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, again.RefreshToken))));
    }

    [Fact]
    public async Task A_person_without_the_role_cannot_use_the_server_whatever_they_approved()
    {
        await using var host = await StartAsync(Guide, Policies, Map);
        var client = await host.RegisterAsync("Example Assistant", scope: "mcp reports.read");
        var (user, _) = await host.UserAsync("guest");
        var tokens = await ConnectAsync(host, user, client, "mcp reports.read", Mcp);

        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, tokens.AccessToken, "/mcp")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, tokens.AccessToken, "/mcp/reports")).StatusCode);
    }

    /// <summary>Section 1 of the guide, on the test host's issuer.</summary>
    private static void Guide(OAuthServerOptions options)
    {
        options.AdditionalResources.Add(Mcp);
        options.AcceptedAudiences.Add(Mcp);
        options.Scopes.Clear();
        options.DefaultScopes.Clear();
        options.Scopes.Add("mcp");
        options.Scopes.Add("reports.read");
        options.Scopes.Add("account");
        options.DynamicRegistration.AllowedScopes.Add("mcp");
        options.DynamicRegistration.AllowedScopes.Add("reports.read");
        options.ProtectedResource.Resources.Add(new OAuthProtectedResourceDefinition
        {
            Resource = Mcp,
            ResourceName = "Example MCP server",
            Scopes = { "mcp", "reports.read" },
            ChallengePaths = { "/mcp" },
        });
        options.AccessTokenClaims.Roles = true;
        options.AccessTokenClaims.UserId = true;
    }

    /// <summary>Section 4 of the guide.</summary>
    private static void Policies(IServiceCollection services)
    {
        services.AddAuthorization(options =>
        {
            options.AddPolicy("mcp", policy => policy
                .RequireOAuthAudience(Mcp)
                .RequireOAuthScope("mcp")
                .RequireRole("Member"));
            options.AddPolicy("reports.read", policy => policy
                .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, OAuthServerConstants.AccessTokenScheme)
                .RequireAuthenticatedUser()
                .RequireOAuthScopeWhenDelegated("reports.read")
                .RequireAssertion(context => !context.User.IsOAuthDelegated() || context.User.HasAudience(Audience)));
        });
    }

    private static void Map(WebApplication app)
    {
        var mcp = app.MapGroup("/mcp").RequireAuthorization("mcp");
        mcp.MapGet("/", (ClaimsPrincipal user, UserManager<IdentityUser> users) => Results.Ok(new { userId = users.GetUserId(user) }));
        // A tool that needs more than the server scope checks it in the handler.
        mcp.MapGet("/reports", (ClaimsPrincipal user) => user.IsOAuthDelegated() && !user.HasOAuthScope("reports.read")
            ? Results.Forbid()
            : Results.Ok(new[] { "Q3" }));
        app.MapGet("/api/reports", () => Results.Ok(new[] { "Q3" })).RequireAuthorization("reports.read");
    }

    private static async Task<TokenPair> ConnectAsync(OAuthTestHost host, HttpClient user, RegisteredClient client, string scope, string resource)
    {
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge, scope: scope, resource: resource);
        var approved = await ApproveAsync(user, id);
        using var anon = host.Client(cookies: false);
        var form = CodeGrant(client, approved["code"], pkce.Verifier);
        form["resource"] = resource;
        return await ReadTokenAsync(await TokenAsync(anon, form));
    }

    private static async Task<HttpResponseMessage> CallAsync(OAuthTestHost host, string accessToken, string path)
    {
        using var api = host.Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await api.GetAsync(path);
    }

    private static async Task<string> AuthorizationIdAsync(OAuthTestHost host, string accessToken)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var token = await tokens.FindByReferenceIdAsync(accessToken);
        Assert.NotNull(token);
        return (await tokens.GetAuthorizationIdAsync(token))!;
    }

    private static async Task AddRoleAsync(OAuthTestHost host, string userId, string role)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        if (!await roles.RoleExistsAsync(role))
        {
            Assert.True((await roles.CreateAsync(new IdentityRole(role))).Succeeded);
        }

        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        Assert.True((await users.AddToRoleAsync((await users.FindByIdAsync(userId))!, role)).Succeeded);
    }

    private static async Task RemoveRoleAsync(OAuthTestHost host, string userId, string role)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        Assert.True((await users.RemoveFromRoleAsync((await users.FindByIdAsync(userId))!, role)).Succeeded);
    }
}
