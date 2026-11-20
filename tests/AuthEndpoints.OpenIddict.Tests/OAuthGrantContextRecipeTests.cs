using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>
/// The "Bind a host context to an OAuth grant" guide, run as written: an organization chosen at consent is bound to the
/// grant, carried by every access token, and re-checked at every refresh.
/// </summary>
public sealed class OAuthGrantContextRecipeTests
{
    [Fact]
    public async Task The_chosen_organization_stays_on_the_grant_and_is_rechecked_at_refresh()
    {
        await using var host = await StartRecipeAsync();
        var members = host.Services.GetRequiredService<OrganizationMembers>();
        var (user, userId) = await host.UserAsync("member");
        members.Add(userId, "org-a");
        members.Add(userId, "org-b");
        members.SetCurrent(userId, "org-a");

        var (client, tokens) = await ConnectAsync(host, user, "org-b");
        Assert.Equal("org-b", await OrganizationAsync(host, tokens.AccessToken));

        // Switching the person's current organization in the browser does not move the assistant.
        members.SetCurrent(userId, "org-a");
        using var anon = host.Client(cookies: false);
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));
        Assert.Equal("org-b", await OrganizationAsync(host, refreshed.AccessToken));

        // Leaving the organization ends the grant at the next refresh.
        members.Remove(userId, "org-b");
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, refreshed.RefreshToken))));
    }

    [Fact]
    public async Task A_security_stamp_change_still_ends_the_grant()
    {
        await using var host = await StartRecipeAsync();
        var members = host.Services.GetRequiredService<OrganizationMembers>();
        var (user, userId) = await host.UserAsync("stamp");
        members.Add(userId, "org-a");
        var (client, tokens) = await ConnectAsync(host, user, "org-a");

        await using (var scope = host.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            await users.UpdateSecurityStampAsync((await users.FindByIdAsync(userId))!);
        }

        using var anon = host.Client(cookies: false);
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken))));
    }

    [Fact]
    public async Task Approving_for_an_organization_the_user_is_not_in_is_refused_and_the_request_stays_open()
    {
        await using var host = await StartRecipeAsync();
        var members = host.Services.GetRequiredService<OrganizationMembers>();
        var (user, userId) = await host.UserAsync("outsider");
        members.Add(userId, "org-a");
        var client = await host.RegisterAsync("Assistant");
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge);

        Assert.Equal(HttpStatusCode.Forbidden, (await ApproveForAsync(user, id, "org-z")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await ApproveForAsync(user, id, "org-a")).StatusCode);
    }

    [Fact]
    public async Task Grants_approved_through_the_built_in_consent_api_keep_working_without_an_organization()
    {
        await using var host = await StartRecipeAsync();
        var (user, _) = await host.UserAsync("plain");
        var (client, tokens) = await host.IssueAsync(user);
        Assert.Null(await OrganizationAsync(host, tokens.AccessToken));

        using var anon = host.Client(cookies: false);
        await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));
    }

    private static Task<OAuthTestHost> StartRecipeAsync()
        => StartAsync(
            services: services =>
            {
                services.AddSingleton<OrganizationMembers>();
                services.AddScoped<IdentityOAuthUserValidator<IdentityUser>>();
                services.Replace(ServiceDescriptor.Scoped<IOAuthUserValidator, OrganizationGrantValidator>());
            },
            map: app =>
            {
                // The guide's approve endpoint.
                app.MapPost("/account/oauth/requests/{id:guid}/approve", async (
                        Guid id, ApproveForOrganization body, HttpContext http, IOAuthConsentService consent, OrganizationMembers members) =>
                    {
                        var userId = http.User.FindFirstValue(ClaimTypes.NameIdentifier)!;
                        if (string.IsNullOrEmpty(body.OrganizationId) || !await members.IsMemberAsync(userId, body.OrganizationId))
                        {
                            return Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: "Not a member of this organization");
                        }

                        // Read by OrganizationGrantValidator.GetStampAsync, which runs inside ApproveAsync.
                        http.Items[OrganizationGrantValidator.OrganizationItem] = body.OrganizationId;
                        var result = await consent.ApproveAsync(id, userId, context =>
                        {
                            var principal = OAuthPrincipals.ForSubject(context.UserId);
                            principal.SetClaim(OrganizationGrantValidator.OrganizationClaim, body.OrganizationId);
                            foreach (var claim in principal.FindAll(OrganizationGrantValidator.OrganizationClaim))
                            {
                                claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
                            }

                            return ValueTask.FromResult<ClaimsPrincipal?>(principal);
                        });

                        return result.Status == OAuthConsentStatus.Approved
                            ? Results.Ok(new { redirectUrl = result.RedirectUrl })
                            : Results.NotFound();
                    })
                    .RequireAuthorization(new Microsoft.AspNetCore.Authorization.AuthorizeAttribute { AuthenticationSchemes = IdentityConstants.ApplicationScheme })
                    .RequireAntiforgery(allowBearer: false);

                // The API reads the organization from the token, never from the user's current organization.
                app.MapGet("/api/organization", (ClaimsPrincipal user) =>
                        Results.Ok(new { organization = user.FindFirst(OrganizationGrantValidator.OrganizationClaim)?.Value }))
                    .RequireAuthorization("api");
            });

    private static async Task<(RegisteredClient Client, TokenPair Tokens)> ConnectAsync(OAuthTestHost host, HttpClient user, string organization)
    {
        var client = await host.RegisterAsync("Assistant");
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge);
        var approve = await ApproveForAsync(user, id, organization);
        var text = await approve.Content.ReadAsStringAsync();
        Assert.True(approve.StatusCode == HttpStatusCode.OK, text);
        var redirect = JsonSerializer.Deserialize<JsonElement>(text).GetProperty("redirectUrl").GetString()!;
        using var anon = host.Client(cookies: false);
        return (client, await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, Query(redirect)["code"], pkce.Verifier))));
    }

    private static async Task<HttpResponseMessage> ApproveForAsync(HttpClient user, Guid id, string organization)
    {
        var csrf = await user.GetFromJsonAsync<JsonElement>("/test/csrf");
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/account/oauth/requests/{id}/approve")
        {
            Content = JsonContent.Create(new { organizationId = organization }),
        };
        request.Headers.Add(CsrfHeader, csrf.GetProperty("token").GetString());
        return await user.SendAsync(request);
    }

    private static async Task<string?> OrganizationAsync(OAuthTestHost host, string accessToken)
    {
        using var api = host.Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        var body = await api.GetFromJsonAsync<JsonElement>("/api/organization");
        return body.GetProperty("organization").GetString();
    }

    internal sealed record ApproveForOrganization(string? OrganizationId);

    /// <summary>Stands in for the host's organization membership table, plus the user's "current organization" in the UI.</summary>
    internal sealed class OrganizationMembers
    {
        private readonly ConcurrentDictionary<(string User, string Organization), bool> _members = new();
        private readonly ConcurrentDictionary<string, string> _current = new();

        public void Add(string userId, string organization) => _members[(userId, organization)] = true;

        public void Remove(string userId, string organization) => _members.TryRemove((userId, organization), out _);

        public void SetCurrent(string userId, string organization) => _current[userId] = organization;

        public ValueTask<bool> IsMemberAsync(string userId, string organization, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(_members.ContainsKey((userId, organization)));
    }

    /// <summary>The guide's validator: the default Identity checks, plus membership of the organization bound at consent.</summary>
    internal sealed class OrganizationGrantValidator(
        IdentityOAuthUserValidator<IdentityUser> identity,
        IHttpContextAccessor http,
        OrganizationMembers members) : IOAuthUserValidator
    {
        public const string OrganizationClaim = "org_id";
        public const string OrganizationItem = "oauth:organization";

        // Runs once, inside ApproveAsync. The value is stored in the grant and handed back to IsValidAsync.
        public async ValueTask<string?> GetStampAsync(string userId, CancellationToken cancellationToken)
        {
            var stamp = await identity.GetStampAsync(userId, cancellationToken);
            return http.HttpContext?.Items[OrganizationItem] is string organization
                ? organization + "|" + stamp
                : stamp;
        }

        // Runs at every code exchange and refresh.
        public async ValueTask<bool> IsValidAsync(string userId, string? stamp, CancellationToken cancellationToken)
        {
            // Identity security stamps never contain '|', so the last one separates the organization.
            var split = stamp?.LastIndexOf('|') ?? -1;
            var organization = split < 0 ? null : stamp![..split];
            var identityStamp = split < 0 ? stamp : stamp![(split + 1)..];
            return await identity.IsValidAsync(userId, identityStamp, cancellationToken)
                && (organization is null || await members.IsMemberAsync(userId, organization, cancellationToken));
        }
    }
}
