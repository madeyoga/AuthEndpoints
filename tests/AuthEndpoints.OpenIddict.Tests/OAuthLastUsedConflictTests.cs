using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Server;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>
/// A last-used write that loses a concurrency race is skipped, and must not leave the request's DbContext with a pending
/// change that makes a later save in the same token request fail.
/// </summary>
public sealed class OAuthLastUsedConflictTests
{
    [Fact]
    public async Task A_skipped_last_used_write_leaves_the_token_request_able_to_save()
    {
        var probe = new Probe();
        await using var host = await StartAsync(
            options =>
            {
                options.RecordLastUsed = true;
                options.LastUsedInterval = TimeSpan.Zero;
            },
            services =>
            {
                services.AddSingleton(probe);
                services.AddOpenIddict().AddServer(server =>
                {
                    // Just before the last-used write: change the grant's row from another DbContext, as a concurrent refresh would.
                    server.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(builder => builder
                        .UseScopedHandler<ChangeGrantElsewhere>()
                        .SetOrder(OpenIddictServerHandlers.AttachSignInParameters.Descriptor.Order + 999));

                    // Just after it: another write through the request's DbContext, as a later handler or host code would.
                    server.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(builder => builder
                        .UseScopedHandler<SaveThroughRequestContext>()
                        .SetOrder(OpenIddictServerHandlers.AttachSignInParameters.Descriptor.Order + 1_001));
                });
            });
        var (user, _) = await host.UserAsync("conflict");
        var (client, tokens) = await host.IssueAsync(user);
        Assert.True(probe.Saves > 0);
        Assert.Empty(probe.Failures);

        // Refresh with a conflict: the token response still succeeds, and so does the later save.
        probe.Conflict = true;
        using var anon = host.Client(cookies: false);
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));
        Assert.True(probe.Conflicts > 0, "The conflict was not forced.");
        Assert.Empty(probe.Failures);
        Assert.Null(await LastUsedAsync(host, client.ClientId));

        // The next refresh records the time again.
        probe.Conflict = false;
        await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, refreshed.RefreshToken)));
        Assert.NotNull(await LastUsedAsync(host, client.ClientId));
        Assert.Empty(probe.Failures);
    }

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

    internal sealed class Probe
    {
        public volatile bool Conflict;
        public int Conflicts;
        public int Saves;
        public List<Exception> Failures { get; } = [];
    }

    private sealed class ChangeGrantElsewhere(Probe probe, IServiceScopeFactory scopes) : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessSignInContext>
    {
        public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignInContext context)
        {
            if (!probe.Conflict
                || context.EndpointType != OpenIddictServerEndpointType.Token
                || context.Principal?.GetAuthorizationId() is not { } id)
            {
                return;
            }

            // A separate scope, so a separate DbContext: the request's tracked copy keeps the old concurrency token.
            // Clearing the properties also removes any last-used time, so the test can see the skipped write.
            await using var scope = scopes.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<TestDb>();
            var changed = await db.Set<OpenIddictEntityFrameworkCoreAuthorization>()
                .Where(authorization => authorization.Id == id)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(authorization => authorization.ConcurrencyToken, Guid.NewGuid().ToString())
                    .SetProperty(authorization => authorization.Properties, (string?)null));
            Interlocked.Add(ref probe.Conflicts, changed);
        }
    }

    private sealed class SaveThroughRequestContext(Probe probe, TestDb db, IOpenIddictAuthorizationManager authorizations)
        : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessSignInContext>
    {
        public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignInContext context)
        {
            if (context.EndpointType != OpenIddictServerEndpointType.Token)
            {
                return;
            }

            try
            {
                db.Roles.Add(new IdentityRole("probe-" + Guid.NewGuid().ToString("N")) { NormalizedName = Guid.NewGuid().ToString("N") });
                await db.SaveChangesAsync(context.CancellationToken);

                // And an update of the same grant through the request's store, which needs its current concurrency token.
                if (context.Principal?.GetAuthorizationId() is { } id
                    && await authorizations.FindByIdAsync(id, context.CancellationToken) is { } authorization)
                {
                    var descriptor = new OpenIddictAuthorizationDescriptor();
                    await authorizations.PopulateAsync(descriptor, authorization, context.CancellationToken);
                    descriptor.Properties["probe"] = System.Text.Json.JsonSerializer.SerializeToElement(true);
                    await authorizations.UpdateAsync(authorization, descriptor, context.CancellationToken);
                }

                Interlocked.Increment(ref probe.Saves);
            }
            catch (Exception ex)
            {
                lock (probe.Failures)
                {
                    probe.Failures.Add(ex);
                }

                throw;
            }
        }
    }
}
