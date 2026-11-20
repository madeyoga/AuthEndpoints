using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using OpenIddict.Abstractions;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>Audit events (<see cref="IOAuthServerEvents"/>) and the opt-in last-used time on grants.</summary>
public sealed class OAuthServerEventTests
{
    [Fact]
    public async Task The_whole_flow_raises_one_event_per_step_with_ids_and_no_secrets()
    {
        var log = new EventLog();
        await using var host = await HostAsync(log);
        var (user, userId) = await host.UserAsync("events");

        var client = await host.RegisterAsync("Audited client");
        var pkce = Pkce.Create();
        var id = await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge, resource: OtherResource);
        var approved = await ApproveAsync(user, id);
        using var anon = host.Client(cookies: false);
        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, approved["code"], pkce.Verifier)));
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));

        var registered = Assert.Single(log.Of(OAuthServerEventType.ClientRegistered));
        Assert.Equal(client.ClientId, registered.ClientId);
        Assert.Equal(OAuthClientKinds.Dynamic, registered.ClientKind);
        Assert.Null(registered.UserId);

        var consent = Assert.Single(log.Of(OAuthServerEventType.ConsentApproved));
        Assert.Equal(userId, consent.UserId);
        Assert.Equal(client.ClientId, consent.ClientId);
        Assert.Equal(OAuthClientKinds.Dynamic, consent.ClientKind);
        Assert.False(string.IsNullOrEmpty(consent.AuthorizationId));
        Assert.Contains("api", consent.Scopes);
        Assert.Equal(OtherResource, consent.Resource);

        var exchanged = Assert.Single(log.Of(OAuthServerEventType.CodeExchanged));
        var refresh = Assert.Single(log.Of(OAuthServerEventType.TokenRefreshed));
        foreach (var item in new[] { exchanged, refresh })
        {
            Assert.Equal(userId, item.UserId);
            Assert.Equal(client.ClientId, item.ClientId);
            Assert.Equal(OAuthClientKinds.Dynamic, item.ClientKind);
            Assert.Equal(consent.AuthorizationId, item.AuthorizationId);
            Assert.Contains("api", item.Scopes);
            Assert.Equal(OtherResource, item.Resource);
        }

        Assert.Equal("authorization_code", exchanged.GrantType);
        Assert.Equal("refresh_token", refresh.GrantType);

        await using (var scope = host.Services.CreateAsyncScope())
        {
            Assert.True(await scope.ServiceProvider.GetRequiredService<IOAuthConsentService>()
                .RevokeAuthorizationAsync(consent.AuthorizationId!));
        }

        var revoked = Assert.Single(log.Of(OAuthServerEventType.AuthorizationRevoked));
        Assert.Equal(OAuthRevokedBy.Admin, revoked.RevokedBy);
        Assert.Equal(userId, revoked.UserId);
        Assert.Equal(client.ClientId, revoked.ClientId);
        Assert.Equal(consent.AuthorizationId, revoked.AuthorizationId);
        Assert.Equal(OtherResource, revoked.Resource);
        Assert.Contains("api", revoked.Scopes);

        // No token, code, or verifier in any event.
        var serialized = JsonSerializer.Serialize(log.All);
        foreach (var secret in new[] { approved["code"], pkce.Verifier, tokens.AccessToken, tokens.RefreshToken, refreshed.AccessToken, refreshed.RefreshToken })
        {
            Assert.DoesNotContain(secret, serialized, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("stamp", serialized, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Denying_consent_raises_consent_denied()
    {
        var log = new EventLog();
        await using var host = await HostAsync(log);
        var (user, userId) = await host.UserAsync("deny");
        var id = await OAuthTestHost.StartAsync(user, SeededClientId, SeededRedirect, Pkce.Create().Challenge);

        Assert.Equal(HttpStatusCode.OK, (await PostConsentAsync(user, id, "deny")).StatusCode);

        var denied = Assert.Single(log.Of(OAuthServerEventType.ConsentDenied));
        Assert.Equal(userId, denied.UserId);
        Assert.Equal(SeededClientId, denied.ClientId);
        Assert.Equal(OAuthClientKinds.Configured, denied.ClientKind);
        Assert.Null(denied.AuthorizationId);
        Assert.Contains("api", denied.Scopes);
        Assert.Empty(log.Of(OAuthServerEventType.ConsentApproved));
    }

    [Fact]
    public async Task A_refresh_refused_by_user_revalidation_raises_grant_refused_and_no_refresh_event()
    {
        var log = new EventLog();
        await using var host = await HostAsync(log);
        var (user, userId) = await host.UserAsync("refused");
        var (client, tokens) = await host.IssueAsync(user);

        await using (var scope = host.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            await users.UpdateSecurityStampAsync((await users.FindByIdAsync(userId))!);
        }

        using var anon = host.Client(cookies: false);
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken))));

        var refused = Assert.Single(log.Of(OAuthServerEventType.GrantRefused));
        Assert.Equal(userId, refused.UserId);
        Assert.Equal(client.ClientId, refused.ClientId);
        Assert.Equal("refresh_token", refused.GrantType);
        Assert.Equal(Assert.Single(log.Of(OAuthServerEventType.CodeExchanged)).AuthorizationId, refused.AuthorizationId);
        Assert.Empty(log.Of(OAuthServerEventType.TokenRefreshed));
        Assert.DoesNotContain(tokens.RefreshToken, JsonSerializer.Serialize(log.All), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_subscriber_that_throws_changes_nothing_and_the_next_one_still_runs()
    {
        var log = new EventLog();
        await using var host = await StartAsync(
            services: services => services.AddSingleton(log),
            server: server => server.AddServerEvents<ThrowingEvents>().AddServerEvents<RecordingEvents>());
        var (user, userId) = await host.UserAsync("throws");

        var (client, tokens) = await host.IssueAsync(user);
        using var anon = host.Client(cookies: false);
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));
        Assert.Equal(userId, await host.SubjectAsync(refreshed.AccessToken));

        Assert.Equal(
            [OAuthServerEventType.ClientRegistered, OAuthServerEventType.ConsentApproved, OAuthServerEventType.CodeExchanged, OAuthServerEventType.TokenRefreshed],
            log.All.Select(item => item.Type).ToArray());
    }

    [Fact]
    public async Task The_same_subscriber_type_is_registered_once()
    {
        var log = new EventLog();
        await using var host = await StartAsync(
            services: services => services.AddSingleton(log),
            server: server => server.AddServerEvents<RecordingEvents>().AddServerEvents<RecordingEvents>());

        await host.RegisterAsync();

        Assert.Single(log.All);
    }

    [Fact]
    public async Task Developer_apps_raise_registered_and_report_each_grant_they_end()
    {
        var log = new EventLog();
        await using var host = await HostAsync(log);
        var (_, ownerId) = await host.UserAsync("owner");
        var (user, userId) = await host.UserAsync("user");

        OAuthDeveloperAppInfo app;
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var created = await scope.ServiceProvider.GetRequiredService<IOAuthDeveloperAppService>().CreateAsync(
                ownerId, new OAuthDeveloperAppInput("Dev app", "https://dev.example", null, [Loopback]), confidential: false);
            app = created.App!;
        }

        var registered = Assert.Single(log.Of(OAuthServerEventType.ClientRegistered));
        Assert.Equal(OAuthClientKinds.DeveloperApp, registered.ClientKind);
        Assert.Equal(ownerId, registered.UserId);
        Assert.Equal(app.ClientId, registered.ClientId);

        var pkce = Pkce.Create();
        var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, app.ClientId, Loopback, pkce.Challenge));
        using var anon = host.Client(cookies: false);
        await ReadTokenAsync(await TokenAsync(anon, CodeGrant(app.ClientId, Loopback, approved["code"], pkce.Verifier)));
        Assert.Equal(OAuthClientKinds.DeveloperApp, Assert.Single(log.Of(OAuthServerEventType.CodeExchanged)).ClientKind);

        await using (var scope = host.Services.CreateAsyncScope())
        {
            Assert.True(await scope.ServiceProvider.GetRequiredService<IOAuthDeveloperAppService>().DeleteAsync(app.Id, ownerId));
        }

        var revoked = Assert.Single(log.Of(OAuthServerEventType.AuthorizationRevoked));
        Assert.Equal(OAuthRevokedBy.ClientDeleted, revoked.RevokedBy);
        Assert.Equal(userId, revoked.UserId);
        Assert.Equal(app.ClientId, revoked.ClientId);
    }

    [Fact]
    public async Task Cleanup_reports_the_grants_of_a_developer_app_whose_owner_was_deleted()
    {
        var log = new EventLog();
        await using var host = await HostAsync(log);
        var (_, ownerId) = await host.UserAsync("gone");
        var (user, userId) = await host.UserAsync("user");
        string clientId;
        await using (var scope = host.Services.CreateAsyncScope())
        {
            clientId = (await scope.ServiceProvider.GetRequiredService<IOAuthDeveloperAppService>().CreateAsync(
                ownerId, new OAuthDeveloperAppInput("Orphan", "https://dev.example", null, [Loopback]), confidential: false)).App!.ClientId;
        }

        var pkce = Pkce.Create();
        var approved = await ApproveAsync(user, await OAuthTestHost.StartAsync(user, clientId, Loopback, pkce.Challenge));
        using var anon = host.Client(cookies: false);
        await ReadTokenAsync(await TokenAsync(anon, CodeGrant(clientId, Loopback, approved["code"], pkce.Verifier)));

        await using (var scope = host.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            await users.DeleteAsync((await users.FindByIdAsync(ownerId))!);
        }

        Assert.Equal(1, (await host.Services.GetRequiredService<IOAuthServerCleanup>().SweepAsync()).OrphanedDeveloperApps);
        var revoked = Assert.Single(log.Of(OAuthServerEventType.AuthorizationRevoked));
        Assert.Equal(OAuthRevokedBy.Cleanup, revoked.RevokedBy);
        Assert.Equal(userId, revoked.UserId);
        Assert.Equal(clientId, revoked.ClientId);
    }

    [Fact]
    public async Task A_new_metadata_document_client_raises_registered_once()
    {
        const string clientUrl = "https://client.example/oauth/client.json";
        var log = new EventLog();
        var documents = new OAuthClientMetadataDocumentTests.FakeDocumentServer();
        documents.Serve(clientUrl, JsonSerializer.Serialize(new { client_id = clientUrl, client_name = "Doc client", redirect_uris = new[] { Loopback } }));
        await using var host = await StartAsync(
            options => options.ClientMetadataDocuments.Enabled = true,
            services =>
            {
                services.AddSingleton(log);
                services.AddHttpClient(OAuthClientMetadataFetcher.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => documents);
                services.RemoveAll<IOAuthClientMetadataDnsResolver>();
                services.AddSingleton<IOAuthClientMetadataDnsResolver>(new PublicDns());
            },
            server: server => server.AddServerEvents<RecordingEvents>());
        var (user, _) = await host.UserAsync("doc");

        await OAuthTestHost.StartAsync(user, clientUrl, Loopback, Pkce.Create().Challenge);
        await OAuthTestHost.StartAsync(user, clientUrl, Loopback, Pkce.Create().Challenge);

        var registered = Assert.Single(log.Of(OAuthServerEventType.ClientRegistered));
        Assert.Equal(clientUrl, registered.ClientId);
        Assert.Equal(OAuthClientKinds.MetadataDocument, registered.ClientKind);
        Assert.Contains("api", registered.Scopes);
    }

    [Fact]
    public async Task Last_used_is_off_by_default()
    {
        await using var host = await StartAsync();
        var (user, _) = await host.UserAsync("off");
        var (client, tokens) = await host.IssueAsync(user);
        using var anon = host.Client(cookies: false);
        await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));

        Assert.Null(await LastUsedAsync(host, client.ClientId));
    }

    [Fact]
    public async Task Last_used_is_written_at_code_exchange_and_then_at_most_once_per_interval()
    {
        var clock = new FakeTimeProvider(TimeProvider.System.GetUtcNow());
        await using var host = await StartAsync(
            options =>
            {
                options.RecordLastUsed = true;
                options.LastUsedInterval = TimeSpan.FromHours(1);
            },
            services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(clock);
            });
        var (user, _) = await host.UserAsync("used");
        var (client, tokens) = await host.IssueAsync(user);
        var exchangedAt = clock.GetUtcNow();
        Assert.Equal(exchangedAt, await LastUsedAsync(host, client.ClientId));

        using var anon = host.Client(cookies: false);
        clock.Advance(TimeSpan.FromMinutes(20));
        var second = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));
        Assert.Equal(exchangedAt, await LastUsedAsync(host, client.ClientId));

        clock.Advance(TimeSpan.FromMinutes(50));
        await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, second.RefreshToken)));
        Assert.Equal(clock.GetUtcNow(), await LastUsedAsync(host, client.ClientId));
    }

    [Fact]
    public async Task A_negative_last_used_interval_fails_startup()
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(() => StartAsync(options => options.LastUsedInterval = TimeSpan.FromSeconds(-1)));
        Assert.Contains("LastUsedInterval", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_approving_user_and_resource_are_stored_on_every_grant_even_with_another_subject()
    {
        await using var host = await StartAsync(server: server => server.AddPrincipalFactory<OrganizationSubject>());
        var (user, userId) = await host.UserAsync("org");
        var (client, _) = await host.IssueAsync(user, resource: OtherResource);

        await using var scope = host.Services.CreateAsyncScope();
        var authorizations = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var applicationId = await applications.GetIdAsync((await applications.FindByClientIdAsync(client.ClientId))!);
        await foreach (var authorization in authorizations.FindByApplicationIdAsync(applicationId!))
        {
            Assert.Equal("org-1", await authorizations.GetSubjectAsync(authorization));
            var record = await OAuthAuthorizationRecord.ReadAsync(authorizations, applications, authorization, default);
            Assert.Equal(userId, record.UserId);
            Assert.Equal(OtherResource, record.Resource);
            return;
        }

        Assert.Fail("No authorization was stored.");
    }

    private static Task<OAuthTestHost> HostAsync(EventLog log)
        => StartAsync(
            services: services => services.AddSingleton(log),
            server: server => server.AddServerEvents<RecordingEvents>());

    private static async Task<DateTimeOffset?> LastUsedAsync(OAuthTestHost host, string clientId)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var authorizations = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var applicationId = await applications.GetIdAsync((await applications.FindByClientIdAsync(clientId))!);
        await foreach (var authorization in authorizations.FindByApplicationIdAsync(applicationId!))
        {
            return (await OAuthAuthorizationRecord.ReadAsync(authorizations, applications, authorization, default)).LastUsedAt;
        }

        return null;
    }

    internal sealed class EventLog
    {
        private readonly ConcurrentQueue<OAuthServerEvent> _events = new();

        public IReadOnlyList<OAuthServerEvent> All => _events.ToArray();

        public void Add(OAuthServerEvent serverEvent) => _events.Enqueue(serverEvent);

        public IReadOnlyList<OAuthServerEvent> Of(OAuthServerEventType type) => All.Where(item => item.Type == type).ToArray();
    }

    internal sealed class RecordingEvents(EventLog log) : IOAuthServerEvents
    {
        public ValueTask OnEventAsync(OAuthServerEvent serverEvent, CancellationToken cancellationToken)
        {
            log.Add(serverEvent);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ThrowingEvents : IOAuthServerEvents
    {
        public ValueTask OnEventAsync(OAuthServerEvent serverEvent, CancellationToken cancellationToken)
            => throw new InvalidOperationException("The audit store is down.");
    }

    private sealed class OrganizationSubject : IOAuthPrincipalFactory
    {
        public ValueTask<System.Security.Claims.ClaimsPrincipal?> CreateAsync(OAuthPrincipalContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult<System.Security.Claims.ClaimsPrincipal?>(OAuthPrincipals.ForSubject("org-1"));
    }

    private sealed class PublicDns : IOAuthClientMetadataDnsResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
            => Task.FromResult(new[] { IPAddress.Parse("93.184.215.14") });
    }
}
