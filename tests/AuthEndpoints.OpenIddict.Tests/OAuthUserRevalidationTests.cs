using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>The approving user is checked again on every code exchange and refresh.</summary>
public sealed class OAuthUserRevalidationTests
{
    [Fact]
    public async Task A_changed_security_stamp_stops_refresh_and_revokes_the_access_token()
    {
        await using var host = await StartAsync();
        var (user, userId) = await host.UserAsync("stamp");
        var (client, tokens) = await host.IssueAsync(user);
        Assert.Equal(userId, await host.SubjectAsync(tokens.AccessToken));

        await ChangeUserAsync(host, userId, (users, u) => users.UpdateSecurityStampAsync(u));

        using var anon = host.Client(cookies: false);
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken))));
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.CallApiAsync(tokens.AccessToken)).StatusCode);
    }

    [Fact]
    public async Task A_locked_out_user_cannot_refresh()
    {
        await using var host = await StartAsync();
        var (user, userId) = await host.UserAsync("locked");
        var (client, tokens) = await host.IssueAsync(user);

        await ChangeUserAsync(host, userId, async (users, u) =>
        {
            await users.SetLockoutEnabledAsync(u, true);
            return await users.SetLockoutEndDateAsync(u, DateTimeOffset.UtcNow.AddDays(1));
        });

        using var anon = host.Client(cookies: false);
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken))));
    }

    [Fact]
    public async Task A_deleted_user_cannot_refresh()
    {
        await using var host = await StartAsync();
        var (user, userId) = await host.UserAsync("deleted");
        var (client, tokens) = await host.IssueAsync(user);

        await ChangeUserAsync(host, userId, (users, u) => users.DeleteAsync(u));

        using var anon = host.Client(cookies: false);
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken))));
    }

    [Fact]
    public async Task A_stamp_change_between_approval_and_code_exchange_rejects_the_code()
    {
        await using var host = await StartAsync();
        var (user, userId) = await host.UserAsync("between");
        var client = await host.RegisterAsync("Between");
        var pkce = Pkce.Create();
        var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge));

        await ChangeUserAsync(host, userId, (users, u) => users.UpdateSecurityStampAsync(u));

        using var anon = host.Client(cookies: false);
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, CodeGrant(client, approved["code"], pkce.Verifier))));
    }

    [Fact]
    public async Task Revalidation_can_be_turned_off()
    {
        await using var host = await StartAsync(options => options.RevalidateUser = false);
        var (user, userId) = await host.UserAsync("off");
        var (client, tokens) = await host.IssueAsync(user);

        await ChangeUserAsync(host, userId, (users, u) => users.UpdateSecurityStampAsync(u));

        using var anon = host.Client(cookies: false);
        await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));
    }

    [Fact]
    public async Task Grant_claims_never_reach_the_access_token_even_when_the_factory_sends_everything()
    {
        await using var host = await StartAsync(services: services =>
        {
            services.RemoveAll<IOAuthPrincipalFactory>();
            services.AddScoped<IOAuthPrincipalFactory, EverythingFactory>();
        });
        var (user, _) = await host.UserAsync("claims");
        var (client, tokens) = await host.IssueAsync(user);

        Assert.DoesNotContain(OAuthServerConstants.UserStampClaim, await ClaimTypesAsync(host, tokens.AccessToken));
        Assert.DoesNotContain(OAuthServerConstants.UserIdClaim, await ClaimTypesAsync(host, tokens.AccessToken));

        using var anon = host.Client(cookies: false);
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));
        var types = await ClaimTypesAsync(host, refreshed.AccessToken);
        Assert.Contains("owner", types);
        Assert.DoesNotContain(OAuthServerConstants.UserStampClaim, types);
    }

    private static async Task<string[]> ClaimTypesAsync(OAuthTestHost host, string accessToken)
    {
        var response = await host.CallApiAsync(accessToken);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return body.GetProperty("claims").EnumerateArray().Select(item => item.GetString()!).ToArray();
    }

    private static async Task ChangeUserAsync(
        OAuthTestHost host, string userId, Func<UserManager<IdentityUser>, IdentityUser, Task<IdentityResult>> change)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var user = await users.FindByIdAsync(userId);
        Assert.True((await change(users, user!)).Succeeded);
    }

    private sealed class EverythingFactory : IOAuthPrincipalFactory
    {
        public ValueTask<System.Security.Claims.ClaimsPrincipal?> CreateAsync(OAuthPrincipalContext context, CancellationToken cancellationToken)
        {
            var principal = OAuthPrincipals.ForSubject(context.UserId);
            global::OpenIddict.Abstractions.OpenIddictExtensions.SetClaim(principal, "owner", context.UserId);
            global::OpenIddict.Abstractions.OpenIddictExtensions.SetDestinations(principal, _ => [global::OpenIddict.Abstractions.OpenIddictConstants.Destinations.AccessToken]);
            return ValueTask.FromResult<System.Security.Claims.ClaimsPrincipal?>(principal);
        }
    }
}

/// <summary>Only a completed sign-in counts at the authorize step.</summary>
public sealed class OAuthSignInStateTests
{
    [Fact]
    public async Task A_pending_two_factor_sign_in_goes_to_login_and_a_finished_one_reaches_consent()
    {
        await using var host = await StartAsync();
        var client = await host.RegisterAsync("2FA");
        using var browser = host.Client();
        var start = await browser.PostAsync($"/test/2fa/start?email=tfa-{Guid.NewGuid():N}@example.test", null);
        Assert.True((await start.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("requiresTwoFactor").GetBoolean());
        var url = AuthorizeUrl(client.ClientId, client.RedirectUri, Pkce.Create().Challenge);

        var pending = await browser.GetAsync(url);
        Assert.StartsWith(LoginUrl, pending.Headers.Location!.ToString(), StringComparison.Ordinal);

        Assert.Equal(HttpStatusCode.NoContent, (await browser.PostAsync("/test/2fa/finish", null)).StatusCode);
        var done = await browser.GetAsync(url);
        Assert.StartsWith(ConsentUrl, done.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unfinished_external_sign_in_goes_to_login()
    {
        await using var host = await StartAsync();
        var client = await host.RegisterAsync("External");
        using var browser = host.Client();
        Assert.Equal(HttpStatusCode.NoContent, (await browser.PostAsync("/test/external-only", null)).StatusCode);

        var response = await browser.GetAsync(AuthorizeUrl(client.ClientId, client.RedirectUri, Pkce.Create().Challenge));
        Assert.StartsWith(LoginUrl, response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Openid_is_neither_advertised_nor_accepted()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("openid");
        var client = await host.RegisterAsync("OpenID");
        using var anon = host.Client(cookies: false);

        var metadata = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-authorization-server");
        Assert.DoesNotContain("openid", metadata.GetProperty("scopes_supported").EnumerateArray().Select(item => item.GetString()));

        var response = await user.GetAsync(AuthorizeUrl(client.ClientId, client.RedirectUri, Pkce.Create().Challenge, scope: "openid api"));
        Assert.DoesNotContain(ConsentUrl, response.Headers.Location?.ToString() ?? "", StringComparison.Ordinal);
        Assert.Contains("invalid_scope", (response.Headers.Location?.ToString() ?? "") + await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }
}
