using System.Collections.Concurrent;
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
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary><see cref="OAuthServerOptions.AccessTokenClaims"/>: the approving user's roles and id on access tokens.</summary>
public sealed class OAuthAccessTokenClaimsTests
{
    [Fact]
    public async Task Both_are_off_by_default()
    {
        await using var host = await StartClaimsAsync(roles: false, userId: false);
        var (user, userId) = await host.UserAsync("claims-off");
        await AddRoleAsync(host, userId, "admin");
        var (_, tokens) = await host.IssueAsync(user);

        var types = await ClaimTypesAsync(host, tokens.AccessToken);
        Assert.DoesNotContain(OpenIddictConstants.Claims.Role, types);
        Assert.DoesNotContain(ClaimTypes.NameIdentifier, types);
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, "/admin", tokens.AccessToken)).StatusCode);
        Assert.Equal("", await BodyAsync(host, "/whoami", tokens.AccessToken));
    }

    [Fact]
    public async Task Roles_pass_RequireRole_and_follow_the_user_at_the_next_refresh()
    {
        await using var host = await StartClaimsAsync(roles: true, userId: false);
        var (user, userId) = await host.UserAsync("claims-roles");
        await AddRoleAsync(host, userId, "admin");
        var (client, tokens) = await host.IssueAsync(user);

        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, "/admin", tokens.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, "/viewer", tokens.AccessToken)).StatusCode);

        await ChangeRolesAsync(host, userId, remove: "admin", add: "viewer");

        // An access token that was already issued keeps its roles until it expires.
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, "/admin", tokens.AccessToken)).StatusCode);

        using var anon = host.Client(cookies: false);
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, "/admin", refreshed.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, "/viewer", refreshed.AccessToken)).StatusCode);
    }

    [Fact]
    public async Task Roles_and_the_user_id_go_to_the_access_token_only()
    {
        var seen = new ConcurrentBag<(string Token, string[] Types)>();
        await using var host = await StartClaimsAsync(roles: true, userId: true, capture: seen);
        var (user, userId) = await host.UserAsync("claims-only-access");
        await AddRoleAsync(host, userId, "admin");
        var (client, tokens) = await host.IssueAsync(user);
        using var anon = host.Client(cookies: false);
        await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));

        Assert.Contains(seen, item => item.Token == "access_token" && item.Types.Contains(OpenIddictConstants.Claims.Role));
        Assert.Contains(seen, item => item.Token == "access_token" && item.Types.Contains(ClaimTypes.NameIdentifier));
        foreach (var (token, types) in seen.Where(item => item.Token != "access_token"))
        {
            Assert.DoesNotContain(OpenIddictConstants.Claims.Role, types);
            Assert.DoesNotContain(ClaimTypes.NameIdentifier, types);
        }

        Assert.Contains(seen, item => item.Token == "refresh_token");
        Assert.Contains(seen, item => item.Token == "authorization_code");
    }

    [Fact]
    public async Task The_user_id_reaches_UserManager_GetUserId_and_the_configured_claim_types()
    {
        await using var host = await StartClaimsAsync(
            roles: false,
            userId: true,
            // The cookie carries the user id under this type, so the authorize step must read it from there too.
            configure: options => options.UserIdClaimType = "uid",
            services: services => services.Configure<IdentityOptions>(identity => identity.ClaimsIdentity.UserIdClaimType = "uid"));
        var (user, userId) = await host.UserAsync("claims-userid");
        var (_, tokens) = await host.IssueAsync(user);

        Assert.Equal(userId, await BodyAsync(host, "/whoami", tokens.AccessToken));
        var types = await ClaimTypesAsync(host, tokens.AccessToken);
        Assert.Contains(ClaimTypes.NameIdentifier, types);
        Assert.Contains("uid", types);
        Assert.DoesNotContain(OpenIddictConstants.Claims.Role, types);
    }

    [Fact]
    public async Task Internal_claims_never_reach_the_access_token()
    {
        await using var host = await StartClaimsAsync(roles: true, userId: true);
        var (user, userId) = await host.UserAsync("claims-internal");
        await AddRoleAsync(host, userId, "admin");
        var (_, tokens) = await host.IssueAsync(user);

        var types = await ClaimTypesAsync(host, tokens.AccessToken);
        Assert.DoesNotContain(OAuthServerConstants.UserIdClaim, types);
        Assert.DoesNotContain(OAuthServerConstants.UserStampClaim, types);
        Assert.DoesNotContain("AspNet.Identity.SecurityStamp", types);
    }

    [Fact]
    public async Task A_factory_that_issues_tokens_for_another_subject_gets_neither()
    {
        await using var host = await StartClaimsAsync(roles: true, userId: true, server: oauth => oauth.AddPrincipalFactory<ServiceAccountFactory>());
        var (user, userId) = await host.UserAsync("claims-other-subject");
        await AddRoleAsync(host, userId, "admin");
        var (_, tokens) = await host.IssueAsync(user);

        Assert.Equal("svc-" + userId, await host.SubjectAsync(tokens.AccessToken));
        var types = await ClaimTypesAsync(host, tokens.AccessToken);
        Assert.DoesNotContain(OpenIddictConstants.Claims.Role, types);
        Assert.DoesNotContain(ClaimTypes.NameIdentifier, types);
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(host, "/admin", tokens.AccessToken)).StatusCode);
    }

    [Fact]
    public async Task A_factory_that_keeps_the_user_as_subject_keeps_its_own_role_claims()
    {
        await using var host = await StartClaimsAsync(roles: true, userId: false, server: oauth => oauth.AddPrincipalFactory<ExtraRoleFactory>());
        var (user, userId) = await host.UserAsync("claims-factory-roles");
        await AddRoleAsync(host, userId, "admin");
        var (_, tokens) = await host.IssueAsync(user);

        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, "/admin", tokens.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(host, "/viewer", tokens.AccessToken)).StatusCode);
    }

    [Fact]
    public async Task Roles_without_an_Identity_role_store_stop_startup()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => StartClaimsAsync(
            roles: true,
            userId: false,
            services: services =>
            {
                services.RemoveAll<IOAuthUserRoles>();
                services.AddScoped<IOAuthUserRoles, NoRoles>();
            }));
        Assert.Contains("AccessTokenClaims.Roles needs Identity roles", error.Message, StringComparison.Ordinal);
    }

    private static Task<OAuthTestHost> StartClaimsAsync(
        bool roles,
        bool userId,
        Action<OAuthServerOptions>? configure = null,
        Action<IServiceCollection>? services = null,
        Action<OAuthServerBuilder>? server = null,
        ConcurrentBag<(string Token, string[] Types)>? capture = null)
        => StartAsync(
            options =>
            {
                options.AccessTokenClaims.Roles = roles;
                options.AccessTokenClaims.UserId = userId;
                configure?.Invoke(options);
            },
            services: collection =>
            {
                collection.Configure<AuthorizationOptions>(options =>
                {
                    options.AddPolicy("admin", policy => policy
                        .AddAuthenticationSchemes(OAuthServerConstants.AccessTokenScheme)
                        .RequireRole("admin"));
                    options.AddPolicy("viewer", policy => policy
                        .AddAuthenticationSchemes(OAuthServerConstants.AccessTokenScheme)
                        .RequireRole("viewer"));
                });
                services?.Invoke(collection);
            },
            server: oauth =>
            {
                server?.Invoke(oauth);
                if (capture is not null)
                {
                    oauth.OpenIddict.AddServer(options => options.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(builder =>
                    {
                        builder.UseInlineHandler(context =>
                        {
                            Record(capture, "authorization_code", context.AuthorizationCodePrincipal);
                            Record(capture, "access_token", context.AccessTokenPrincipal);
                            Record(capture, "refresh_token", context.RefreshTokenPrincipal);
                            Record(capture, "id_token", context.IdentityTokenPrincipal);
                            return ValueTask.CompletedTask;
                        });
                        // After every token is generated, before the response is written.
                        builder.SetOrder(OpenIddictServerHandlers.AttachSignInParameters.Descriptor.Order + 1_000);
                    }));
                }
            },
            map: app =>
            {
                app.MapGet("/admin", () => Results.Ok()).RequireAuthorization("admin");
                app.MapGet("/viewer", () => Results.Ok()).RequireAuthorization("viewer");
                app.MapGet("/whoami", (ClaimsPrincipal principal, UserManager<IdentityUser> users) => Results.Text(users.GetUserId(principal) ?? ""))
                    .RequireAuthorization("api");
            });

    private static void Record(ConcurrentBag<(string, string[])> capture, string token, ClaimsPrincipal? principal)
    {
        if (principal is not null)
        {
            capture.Add((token, principal.Claims.Select(claim => claim.Type).Distinct().ToArray()));
        }
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

    /// <summary>Changes roles without touching the security stamp, so the grant stays valid.</summary>
    private static async Task ChangeRolesAsync(OAuthTestHost host, string userId, string remove, string add)
    {
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var user = (await users.FindByIdAsync(userId))!;
            var stamp = await users.GetSecurityStampAsync(user);
            Assert.True((await users.RemoveFromRoleAsync(user, remove)).Succeeded);
            Assert.Equal(stamp, await users.GetSecurityStampAsync(user));
        }

        await AddRoleAsync(host, userId, add);
    }

    private static async Task<string[]> ClaimTypesAsync(OAuthTestHost host, string accessToken)
    {
        var response = await host.CallApiAsync(accessToken);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return body.GetProperty("claims").EnumerateArray().Select(item => item.GetString()!).ToArray();
    }

    private static async Task<HttpResponseMessage> CallAsync(OAuthTestHost host, string path, string accessToken)
    {
        using var api = host.Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await api.GetAsync(path);
    }

    private static async Task<string> BodyAsync(OAuthTestHost host, string path, string accessToken)
    {
        var response = await CallAsync(host, path, accessToken);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode} {text}");
        return text;
    }

    private sealed class ServiceAccountFactory : IOAuthPrincipalFactory
    {
        public ValueTask<ClaimsPrincipal?> CreateAsync(OAuthPrincipalContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult<ClaimsPrincipal?>(OAuthPrincipals.ForSubject("svc-" + context.UserId));
    }

    private sealed class ExtraRoleFactory : IOAuthPrincipalFactory
    {
        public ValueTask<ClaimsPrincipal?> CreateAsync(OAuthPrincipalContext context, CancellationToken cancellationToken)
        {
            var principal = OAuthPrincipals.ForSubject(context.UserId);
            principal.AddClaim(OpenIddictConstants.Claims.Role, "viewer");
            principal.SetDestinations(claim => claim.Type == OpenIddictConstants.Claims.Role
                ? [OpenIddictConstants.Destinations.AccessToken]
                : []);
            return ValueTask.FromResult<ClaimsPrincipal?>(principal);
        }
    }

    private sealed class NoRoles : IOAuthUserRoles
    {
        public bool Supported => false;

        public ValueTask<IReadOnlyList<string>> GetRolesAsync(string userId, CancellationToken cancellationToken)
            => ValueTask.FromResult<IReadOnlyList<string>>([]);
    }
}
