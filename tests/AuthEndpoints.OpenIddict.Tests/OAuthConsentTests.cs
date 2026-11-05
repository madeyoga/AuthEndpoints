using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using OpenIddict.Abstractions;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

public sealed class OAuthConsentTests
{
    [Fact]
    public async Task Deny_returns_access_denied_and_the_request_cannot_be_reused()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("deny");
        var client = await host.RegisterAsync("Denied");
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge, "deny-me");

        var denied = await PostConsentAsync(user, id, "deny");
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        var query = Query((await denied.Content.ReadFromJsonAsync<OAuthConsentRedirect>())!.RedirectUrl);
        Assert.Equal("access_denied", query["error"]);
        Assert.Equal("deny-me", query["state"]);
        Assert.Equal(Issuer, query["iss"]);
        Assert.False(query.ContainsKey("code"));

        Assert.Equal(HttpStatusCode.NotFound, (await PostConsentAsync(user, id, "approve")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await user.GetAsync($"/oauth/requests/{id}")).StatusCode);
    }

    [Fact]
    public async Task An_approved_request_cannot_be_approved_again()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("once");
        var client = await host.RegisterAsync("Once");
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);

        await ApproveAsync(user, id);
        Assert.Equal(HttpStatusCode.NotFound, (await PostConsentAsync(user, id, "approve")).StatusCode);
    }

    [Fact]
    public async Task Someone_elses_request_is_not_found()
    {
        await using var host = await StartAsync();
        var (owner, _) = await host.UserAsync("owner");
        var (stranger, _) = await host.UserAsync("stranger");
        var client = await host.RegisterAsync("Private");
        var id = await OAuthTestHost.StartAsync(owner, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);

        Assert.Equal(HttpStatusCode.NotFound, (await stranger.GetAsync($"/oauth/requests/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await PostConsentAsync(stranger, id, "approve")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await PostConsentAsync(stranger, id, "deny")).StatusCode);

        var card = await owner.GetFromJsonAsync<OAuthConsentCard>($"/oauth/requests/{id}");
        Assert.Equal("Private", card!.ClientName);
    }

    [Fact]
    public async Task Consent_endpoints_need_a_signed_in_user_and_a_csrf_token()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("csrf");
        var client = await host.RegisterAsync("CSRF");
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);
        using var anon = host.Client();

        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync($"/oauth/requests/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await user.PostAsync($"/oauth/requests/{id}/approve", null)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync($"/oauth/requests/{id}")).StatusCode);
    }

    [Fact]
    public async Task A_consent_request_expires()
    {
        var clock = new FakeTimeProvider(TimeProvider.System.GetUtcNow());
        await using var host = await StartAsync(
            options => options.ConsentLifetime = TimeSpan.FromMinutes(10),
            services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(clock);
            });
        var (user, _) = await host.UserAsync("expiry");
        var client = await host.RegisterAsync("Expiry");
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync($"/oauth/requests/{id}")).StatusCode);

        clock.Advance(TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.NotFound, (await user.GetAsync($"/oauth/requests/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await PostConsentAsync(user, id, "approve")).StatusCode);
    }

    [Fact]
    public async Task A_custom_principal_factory_sets_the_token_subject()
    {
        await using var host = await StartAsync(services: services =>
        {
            services.RemoveAll<IOAuthPrincipalFactory>();
            services.AddScoped<IOAuthPrincipalFactory, AgentPrincipalFactory>();
        });
        var (user, userId) = await host.UserAsync("agent");
        var (_, tokens) = await host.IssueAsync(user);

        Assert.Equal("agent-of-" + userId, await host.SubjectAsync(tokens.AccessToken));
    }

    [Fact]
    public async Task A_declined_approval_does_not_consume_the_request()
    {
        await using var host = await StartAsync(map: app => app.MapPost("/custom/{id:guid}/approve", async (
            Guid id, string? pick, HttpContext http, IOAuthConsentService consent) =>
        {
            var userId = http.User.FindFirst(ClaimTypes.NameIdentifier)!.Value;
            var result = await consent.ApproveAsync(id, userId, context => ValueTask.FromResult(
                pick is null ? null : OAuthPrincipals.ForSubject(pick + ":" + context.Request.ClientId)));
            return Results.Ok(new { status = result.Status.ToString(), result.RedirectUrl, result.AuthorizationId });
        }).RequireAuthorization());
        var (user, _) = await host.UserAsync("custom");
        var client = await host.RegisterAsync("Custom");
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge);

        var declined = await user.PostAsync($"/custom/{id}/approve", null);
        Assert.Equal("Declined", (await declined.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>()).GetProperty("status").GetString());
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync($"/oauth/requests/{id}")).StatusCode);

        var approved = await (await user.PostAsync($"/custom/{id}/approve?pick=agent", null)).Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.Equal("Approved", approved.GetProperty("status").GetString());
        Assert.False(string.IsNullOrEmpty(approved.GetProperty("authorizationId").GetString()));
        var code = Query(approved.GetProperty("redirectUrl").GetString()!)["code"];
        using var anon = host.Client(cookies: false);
        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, code, pkce.Verifier)));
        Assert.Equal("agent:" + client.ClientId, await host.SubjectAsync(tokens.AccessToken));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_request_whose_client_was_deleted_is_not_found_and_issues_no_code(bool seeded)
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("deleted-client");
        var client = seeded ? new RegisteredClient(SeededClientId, SeededRedirect) : await host.RegisterAsync("Doomed");
        var approveId = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);
        var denyId = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);

        await DeleteClientAsync(host, client.ClientId);

        Assert.Equal(HttpStatusCode.NotFound, (await user.GetAsync($"/oauth/requests/{approveId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await PostConsentAsync(user, approveId, "approve")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await PostConsentAsync(user, denyId, "deny")).StatusCode);
        Assert.True(await IsConsumedAsync(host, approveId));
        Assert.True(await IsConsumedAsync(host, denyId));
        await using var scope = host.Services.CreateAsyncScope();
        Assert.Equal(0, await scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>().CountAsync());
    }

    [Fact]
    public async Task A_client_deleted_while_the_principal_is_built_is_not_found()
    {
        await using var host = await StartAsync(map: app => app.MapPost("/racing/{id:guid}/approve", async (
            Guid id, HttpContext http, IOAuthConsentService consent, IOpenIddictApplicationManager applications) =>
        {
            var userId = http.User.FindFirst(ClaimTypes.NameIdentifier)!.Value;
            var result = await consent.ApproveAsync(id, userId, async context =>
            {
                await applications.DeleteAsync((await applications.FindByClientIdAsync(context.Request.ClientId))!);
                return OAuthPrincipals.ForSubject(context.UserId);
            });
            return Results.Ok(new { status = result.Status.ToString() });
        }).RequireAuthorization());
        var (user, _) = await host.UserAsync("racing");
        var client = await host.RegisterAsync("Racing");
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);

        var response = await user.PostAsync($"/racing/{id}/approve", null);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, text);
        Assert.Equal("NotFound", System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(text).GetProperty("status").GetString());
        Assert.True(await IsConsumedAsync(host, id));
    }

    internal static async Task DeleteClientAsync(OAuthTestHost host, string clientId)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await applications.DeleteAsync((await applications.FindByClientIdAsync(clientId))!);
    }

    internal static async Task<bool> IsConsumedAsync(OAuthTestHost host, Guid id)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TestDb>();
        var row = await db.Set<OAuthRequest<string>>().AsNoTracking().SingleAsync(request => request.Id == id);
        return row.ConsumedAt is not null;
    }

    private sealed class AgentPrincipalFactory : IOAuthPrincipalFactory
    {
        public ValueTask<ClaimsPrincipal?> CreateAsync(OAuthPrincipalContext context, CancellationToken cancellationToken)
        {
            var principal = OAuthPrincipals.ForSubject("agent-of-" + context.UserId);
            principal.SetClaim("owner", context.UserId);
            principal.SetDestinations(_ => [OpenIddictConstants.Destinations.AccessToken]);
            return ValueTask.FromResult<ClaimsPrincipal?>(principal);
        }
    }
}
