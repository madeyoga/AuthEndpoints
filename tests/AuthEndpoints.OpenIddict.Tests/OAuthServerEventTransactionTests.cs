using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using static AuthEndpoints.OpenIddict.Tests.OAuthServerEventTests;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>Events raised while the host has a transaction open wait for its commit, and are dropped on rollback.</summary>
public sealed class OAuthServerEventTransactionTests
{
    [Theory]
    [InlineData("rollback", 0)]
    [InlineData("commit", 1)]
    [InlineData("commit-sync", 1)]
    [InlineData("none", 1)]
    public async Task Approving_follows_the_host_transaction(string mode, int raised)
    {
        var log = new EventLog();
        await using var host = await HostAsync(log);
        var (user, userId) = await host.UserAsync(mode);
        var id = await PendingAsync(host, user);

        var response = await user.PostAsync($"/test/approve-in-transaction/{id}?mode={mode}", null);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, text);

        // The endpoint reports how many ConsentApproved events subscribers had seen before the transaction ended.
        Assert.Equal(mode == "none" ? "1" : "0", text);
        var events = log.Of(OAuthServerEventType.ConsentApproved);
        Assert.Equal(raised, events.Count);
        if (raised == 1)
        {
            Assert.Equal(userId, events[0].UserId);
            Assert.False(string.IsNullOrEmpty(events[0].AuthorizationId));
        }
    }

    [Fact]
    public async Task Revoking_a_connected_app_inside_a_transaction_follows_its_outcome()
    {
        var log = new EventLog();
        await using var host = await HostAsync(log);
        var (user, userId) = await host.UserAsync("revoke");
        await host.IssueAsync(user);
        string authorizationId;
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var apps = await scope.ServiceProvider.GetRequiredService<IOAuthConnectedAppService>().ListAsync(userId);
            authorizationId = Assert.Single(apps).AuthorizationId;
        }

        // Rolled back: nothing raised, and the grant is still there.
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TestDb>();
            var apps = scope.ServiceProvider.GetRequiredService<IOAuthConnectedAppService>();
            await using var transaction = await db.Database.BeginTransactionAsync();
            Assert.True(await apps.RevokeAsync(userId, authorizationId));
            await transaction.RollbackAsync();
        }

        Assert.Empty(log.Of(OAuthServerEventType.AuthorizationRevoked));

        // Committed: raised once.
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TestDb>();
            var apps = scope.ServiceProvider.GetRequiredService<IOAuthConnectedAppService>();
            await using var transaction = await db.Database.BeginTransactionAsync();
            Assert.True(await apps.RevokeAsync(userId, authorizationId));
            await transaction.CommitAsync();
        }

        var revoked = Assert.Single(log.Of(OAuthServerEventType.AuthorizationRevoked));
        Assert.Equal(authorizationId, revoked.AuthorizationId);
        Assert.Equal(OAuthRevokedBy.User, revoked.RevokedBy);
    }

    [Fact]
    public async Task A_pooled_DbContext_gets_the_interceptor_too()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ae-pool-{Guid.NewGuid():N}.sqlite");
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContextPool<TestDb>(options => options.UseSqlite($"Data Source={path};Pooling=False"));
        services.AddIdentityCore<IdentityUser>().AddEntityFrameworkStores<TestDb>();
        services.AddAuthEndpointsOpenIddict<IdentityUser>().AddEntityFrameworkStores<TestDb>();
        await using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = false });
        await using var scope = provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TestDb>();
        Assert.Contains(
            provider.GetRequiredService<OAuthEventTransactions>(),
            db.GetService<Microsoft.EntityFrameworkCore.Infrastructure.IDbContextOptions>()
                .FindExtension<Microsoft.EntityFrameworkCore.Infrastructure.CoreOptionsExtension>()!.Interceptors!);
        File.Delete(path);
    }

    private static Task<OAuthTestHost> HostAsync(EventLog log)
        => StartAsync(
            services: services => services.AddSingleton(log),
            server: server => server.AddServerEvents<RecordingEvents>(),
            map: app => app.MapPost("/test/approve-in-transaction/{id:guid}", async (
                Guid id, string mode, HttpContext http, TestDb db, IOAuthConsentService consent, UserManager<IdentityUser> users) =>
            {
                // The README's own approve endpoint: the host's rows and the OpenIddict rows commit together.
                var userId = users.GetUserId(http.User)!;
                if (mode == "none")
                {
                    await consent.ApproveAsync(id, userId);
                    return Results.Text(log.Of(OAuthServerEventType.ConsentApproved).Count.ToString(CultureInfo.InvariantCulture));
                }

                var transaction = mode == "commit-sync" ? db.Database.BeginTransaction() : await db.Database.BeginTransactionAsync();
                await using (transaction)
                {
                    var result = await consent.ApproveAsync(id, userId);
                    if (result.Status != OAuthConsentStatus.Approved)
                    {
                        return Results.BadRequest(result.Status.ToString());
                    }

                    var seen = log.Of(OAuthServerEventType.ConsentApproved).Count.ToString(CultureInfo.InvariantCulture);
                    switch (mode)
                    {
                        case "commit":
                            await transaction.CommitAsync();
                            break;
                        case "commit-sync":
                            transaction.Commit();
                            break;
                        default:
                            await transaction.RollbackAsync();
                            break;
                    }

                    return Results.Text(seen);
                }
            }).RequireAuthorization().DisableAntiforgery());

    private static async Task<Guid> PendingAsync(OAuthTestHost host, HttpClient user)
    {
        var client = await host.RegisterAsync("Transactional");
        return await OAuthTestHost.StartAsync(user, client.ClientId, client.RedirectUri, Pkce.Create().Challenge);
    }
}
