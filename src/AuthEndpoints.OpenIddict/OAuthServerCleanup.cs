using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace AuthEndpoints.OpenIddict;

/// <summary>Rows removed by one cleanup pass.</summary>
/// <param name="UnusedClients">Dynamically registered clients that no user approved.</param>
/// <param name="ExpiredRequests">Expired consent requests.</param>
/// <param name="Tokens">Old expired or revoked tokens.</param>
/// <param name="Authorizations">Old revoked or orphaned authorizations.</param>
/// <param name="OrphanedDeveloperApps">Developer app clients whose <c>OAuthDeveloperApps</c> row is gone, for example because the owner was deleted.</param>
public sealed record OAuthCleanupResult(int UnusedClients, int ExpiredRequests, long Tokens, long Authorizations, int OrphanedDeveloperApps = 0);

/// <summary>
/// Deletes dynamically registered clients nobody approved, developer app clients without an owner, expired consent requests, and old
/// expired or revoked tokens and authorizations. The background service calls it on <see cref="OAuthServerOptions.CleanupInterval"/>.
/// </summary>
public interface IOAuthServerCleanup
{
    Task<OAuthCleanupResult> SweepAsync(CancellationToken cancellationToken = default);
}

internal sealed class OAuthServerCleanup<TContext, TKey>(
    IServiceScopeFactory scopes,
    TimeProvider clock,
    IOptions<OAuthServerOptions> options) : IOAuthServerCleanup
    where TContext : DbContext
    where TKey : IEquatable<TKey>
{
    public async Task<OAuthCleanupResult> SweepAsync(CancellationToken cancellationToken = default)
    {
        await using var scope = scopes.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
        var authorizations = services.GetRequiredService<IOpenIddictAuthorizationManager>();
        var tokens = services.GetRequiredService<IOpenIddictTokenManager>();
        var db = services.GetRequiredService<TContext>();
        var settings = options.Value;
        var now = clock.GetUtcNow();

        var clients = await DeleteUnusedClientsAsync(applications, authorizations, tokens, settings, now, cancellationToken);
        var orphans = await DeleteOrphanedDeveloperAppsAsync(db, applications, authorizations, tokens, cancellationToken);
        var requests = await db.Set<OAuthRequest<TKey>>()
            .Where(request => request.ExpiresAt <= now)
            .ExecuteDeleteAsync(cancellationToken);
        var threshold = now - settings.PruneAfter;
        var prunedTokens = await tokens.PruneAsync(threshold, cancellationToken);
        var prunedAuthorizations = await authorizations.PruneAsync(threshold, cancellationToken);
        return new OAuthCleanupResult(clients, requests, prunedTokens, prunedAuthorizations, orphans);
    }

    private static async Task<int> DeleteOrphanedDeveloperAppsAsync(
        TContext db,
        IOpenIddictApplicationManager applications,
        IOpenIddictAuthorizationManager authorizations,
        IOpenIddictTokenManager tokens,
        CancellationToken cancellationToken)
    {
        var marked = new List<(object Application, Guid Id)>();
        await foreach (var application in applications.ListAsync(cancellationToken: cancellationToken))
        {
            if (await OAuthDeveloperAppService<TContext, TKey>.DeveloperAppIdAsync(applications, application, cancellationToken) is { } id)
            {
                marked.Add((application, id));
            }
        }

        if (marked.Count == 0)
        {
            return 0;
        }

        // Rows are written before their application, so a missing row never belongs to an app being created.
        var ids = marked.Select(item => item.Id).ToList();
        var existing = await db.Set<OAuthDeveloperApp<TKey>>()
            .Where(app => ids.Contains(app.Id))
            .Select(app => app.Id)
            .ToListAsync(cancellationToken);
        var kept = existing.ToHashSet();
        var deleted = 0;
        foreach (var (application, id) in marked)
        {
            if (kept.Contains(id))
            {
                continue;
            }

            await OAuthDeveloperAppService<TContext, TKey>.DeleteApplicationAsync(
                applications, tokens, authorizations, application, cancellationToken);
            deleted++;
        }

        return deleted;
    }

    private static async Task<int> DeleteUnusedClientsAsync(
        IOpenIddictApplicationManager applications,
        IOpenIddictAuthorizationManager authorizations,
        IOpenIddictTokenManager tokens,
        OAuthServerOptions settings,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var lifetime = settings.DynamicRegistration.UnusedClientLifetime > TimeSpan.Zero
            ? settings.DynamicRegistration.UnusedClientLifetime
            : TimeSpan.FromHours(24);
        var candidates = new List<object>();
        await foreach (var application in applications.ListAsync(cancellationToken: cancellationToken))
        {
            candidates.Add(application);
        }

        var deleted = 0;
        foreach (var application in candidates)
        {
            // Only dynamically registered clients carry this setting. Seeded clients are never swept.
            var applicationSettings = await applications.GetSettingsAsync(application, cancellationToken);
            if (!applicationSettings.TryGetValue(OAuthServerConstants.CreatedAtSetting, out var raw)
                || !DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var created)
                || now - created < lifetime)
            {
                continue;
            }

            var applicationId = await applications.GetIdAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(applicationId) || await HasAuthorizationAsync(authorizations, applicationId, cancellationToken))
            {
                continue;
            }

            var pending = new List<object>();
            await foreach (var token in tokens.FindByApplicationIdAsync(applicationId, cancellationToken))
            {
                pending.Add(token);
            }

            foreach (var token in pending)
            {
                await tokens.DeleteAsync(token, cancellationToken);
            }

            await applications.DeleteAsync(application, cancellationToken);
            deleted++;
        }

        return deleted;
    }

    private static async Task<bool> HasAuthorizationAsync(
        IOpenIddictAuthorizationManager authorizations, string applicationId, CancellationToken cancellationToken)
    {
        await foreach (var _ in authorizations.FindByApplicationIdAsync(applicationId, cancellationToken))
        {
            return true;
        }

        return false;
    }
}

internal sealed partial class OAuthServerCleanupService(
    IOAuthServerCleanup cleanup,
    IOptions<OAuthServerOptions> options,
    TimeProvider clock,
    ILogger<OAuthServerCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = options.Value.CleanupInterval;
        if (interval <= TimeSpan.Zero)
        {
            return;
        }

        using var timer = new PeriodicTimer(interval, clock);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    await cleanup.SweepAsync(stoppingToken);
                }
                catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
                {
                    LogSweepFailed(ex);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "OAuth server cleanup failed")]
    private partial void LogSweepFailed(Exception ex);
}
