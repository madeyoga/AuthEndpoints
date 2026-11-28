using System.Data.Common;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;

namespace AuthEndpoints.OpenIddict;

internal static class OAuthJson
{
    /// <summary>How OpenIddict's EF Core store writes property values: non-ASCII characters are not escaped.</summary>
    public static readonly JsonSerializerOptions Relaxed = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
}

/// <summary>Checks that the context maps the OAuth server tables.</summary>
internal static class OAuthServerModel
{
    public static void Ensure<TKey>(DbContext db)
        where TKey : IEquatable<TKey>
    {
        var model = db.Model;
        if (model.FindEntityType(typeof(OAuthRequest<TKey>)) is null
            || model.FindEntityType(typeof(OAuthDeveloperApp<TKey>)) is null
            || model.FindEntityType(typeof(OpenIddictEntityFrameworkCoreApplication)) is null)
        {
            throw new InvalidOperationException(
                $"{db.GetType().Name} has no OAuth server tables for user key type {typeof(TKey).Name}. " +
                "Call modelBuilder.UseAuthEndpointsOpenIddict<TUser>() in OnModelCreating, with the same TUser as AddOAuthServer, then add a migration.");
        }
    }
}

/// <summary>EF Core <see cref="IOAuthRequestStore{TKey}"/>. Reads are untracked, and consuming is one conditional update.</summary>
internal sealed class EntityFrameworkOAuthRequestStore<TContext, TKey> : IOAuthRequestStore<TKey>
    where TContext : DbContext
    where TKey : IEquatable<TKey>
{
    private readonly TContext _db;

    public EntityFrameworkOAuthRequestStore(TContext db)
    {
        OAuthServerModel.Ensure<TKey>(db);
        _db = db;
    }

    private DbSet<OAuthRequest<TKey>> Requests => _db.Set<OAuthRequest<TKey>>();

    public async Task CreateAsync(OAuthRequest<TKey> request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        Requests.Add(request);
        try
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
        finally
        {
            _db.Entry(request).State = EntityState.Detached;
        }
    }

    public Task<OAuthRequest<TKey>?> FindLiveAsync(Guid id, TKey userId, DateTimeOffset now, CancellationToken cancellationToken)
        => Requests.AsNoTracking()
            .FirstOrDefaultAsync(
                request => request.Id == id && request.UserId.Equals(userId)
                    && request.ConsumedAt == null && request.ExpiresAt > now,
                cancellationToken);

    public async Task<bool> TryConsumeAsync(Guid id, TKey userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var won = await Requests
            .Where(request => request.Id == id && request.UserId.Equals(userId)
                && request.ConsumedAt == null && request.ExpiresAt > now)
            .ExecuteUpdateAsync(set => set.SetProperty(request => request.ConsumedAt, now), cancellationToken);
        return won == 1;
    }

    public Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken)
        => Requests.Where(request => request.ExpiresAt <= now).ExecuteDeleteAsync(cancellationToken);
}

/// <summary>EF Core <see cref="IOAuthDeveloperAppStore{TKey}"/>. Reads are untracked, and writes leave nothing tracked.</summary>
internal sealed class EntityFrameworkOAuthDeveloperAppStore<TContext, TKey> : IOAuthDeveloperAppStore<TKey>
    where TContext : DbContext
    where TKey : IEquatable<TKey>
{
    private readonly TContext _db;

    public EntityFrameworkOAuthDeveloperAppStore(TContext db)
    {
        OAuthServerModel.Ensure<TKey>(db);
        _db = db;
    }

    private DbSet<OAuthDeveloperApp<TKey>> Apps => _db.Set<OAuthDeveloperApp<TKey>>();

    public async Task<IReadOnlyList<OAuthDeveloperApp<TKey>>> ListByOwnerAsync(TKey ownerId, CancellationToken cancellationToken)
        => await Apps.AsNoTracking()
            .Where(app => app.OwnerId.Equals(ownerId))
            .OrderBy(app => app.CreatedAt)
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<OAuthDeveloperApp<TKey>>> ListByStatusAsync(
        OAuthDeveloperAppStatus status,
        CancellationToken cancellationToken)
        => await Apps.AsNoTracking()
            .Where(app => app.Status == status)
            .OrderBy(app => app.CreatedAt)
            .ToListAsync(cancellationToken);

    public Task<OAuthDeveloperApp<TKey>?> FindAsync(Guid id, CancellationToken cancellationToken)
        => Apps.AsNoTracking().FirstOrDefaultAsync(app => app.Id == id, cancellationToken);

    public async Task<IReadOnlyList<OAuthDeveloperApp<TKey>>> FindByIdsAsync(
        IReadOnlyCollection<Guid> ids,
        CancellationToken cancellationToken)
        => ids.Count == 0
            ? []
            : await Apps.AsNoTracking().Where(app => ids.Contains(app.Id)).ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<OAuthDeveloperApp<TKey>>> FindByClientIdsAsync(
        IReadOnlyCollection<string> clientIds,
        CancellationToken cancellationToken)
        => clientIds.Count == 0
            ? []
            : await Apps.AsNoTracking().Where(app => clientIds.Contains(app.ClientId)).ToListAsync(cancellationToken);

    public Task<int> CountByOwnerAsync(TKey ownerId, CancellationToken cancellationToken)
        => Apps.CountAsync(app => app.OwnerId.Equals(ownerId), cancellationToken);

    public async Task CreateAsync(OAuthDeveloperApp<TKey> app, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(app);
        Apps.Add(app);
        try
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
        finally
        {
            _db.Entry(app).State = EntityState.Detached;
        }
    }

    public async Task<bool> UpdateDetailsAsync(
        Guid id,
        string name,
        string homepageUrl,
        string? description,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken)
        => await Apps
            .Where(row => row.Id == id)
            .ExecuteUpdateAsync(
                set => set
                    .SetProperty(row => row.Name, name)
                    .SetProperty(row => row.HomepageUrl, homepageUrl)
                    .SetProperty(row => row.Description, description)
                    .SetProperty(row => row.UpdatedAt, updatedAt),
                cancellationToken) == 1;

    public async Task<bool> SetStatusAsync(
        Guid id,
        OAuthDeveloperAppStatus status,
        OAuthDeveloperAppStatus? expected,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken)
    {
        var query = Apps.Where(row => row.Id == id);
        if (expected is { } current)
        {
            query = query.Where(row => row.Status == current);
        }

        return await query.ExecuteUpdateAsync(
            set => set
                .SetProperty(row => row.Status, status)
                .SetProperty(row => row.UpdatedAt, updatedAt),
            cancellationToken) == 1;
    }

    public async Task<bool> SetSecretCreatedAtAsync(Guid id, DateTimeOffset secretCreatedAt, CancellationToken cancellationToken)
        => await Apps
            .Where(row => row.Id == id)
            .ExecuteUpdateAsync(
                set => set
                    .SetProperty(row => row.SecretCreatedAt, secretCreatedAt)
                    .SetProperty(row => row.UpdatedAt, secretCreatedAt),
                cancellationToken) == 1;

    public async Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken)
        => await Apps.Where(app => app.Id == id).ExecuteDeleteAsync(cancellationToken) > 0;

    public Task<bool> IsActiveAsync(Guid id, string clientId, CancellationToken cancellationToken)
        => Apps.AnyAsync(
            app => app.Id == id && app.ClientId == clientId && app.Status == OAuthDeveloperAppStatus.Active,
            cancellationToken);
}

/// <summary>
/// EF Core <see cref="IOAuthServerQueries"/>: reads OpenIddict's tables untracked, with each grant's client in the same
/// query. Untracked matters: a bulk revoke or delete that follows must not find stale tracked copies.
/// </summary>
internal sealed class EntityFrameworkOAuthServerQueries<TContext>(TContext db) : IOAuthServerQueries
    where TContext : DbContext
{
    public async Task<IReadOnlyList<OAuthAuthorizationRecord>> ListLiveGrantsAsync(
        string userId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(userId);
        var utc = now.UtcDateTime;
        // The database narrows by subject or by the stored user id's text; the caller then checks the user exactly.
        var relaxed = JsonSerializer.Serialize(userId, OAuthJson.Relaxed);
        var strict = JsonSerializer.Serialize(userId);
        const string valid = OpenIddictConstants.Statuses.Valid;
        const string permanent = OpenIddictConstants.AuthorizationTypes.Permanent;
        var rows = await QueryAsync(
            authorization => authorization.Status == valid
                && authorization.Application != null
                && (authorization.Subject == userId
                    || (authorization.Properties != null
                        && (authorization.Properties.Contains(relaxed) || authorization.Properties.Contains(strict))))
                && (authorization.Type == permanent
                    || authorization.Tokens.Any(token => token.Status == valid && token.ExpirationDate > utc)),
            cancellationToken);
        return rows.Where(row => string.Equals(row.UserId, userId, StringComparison.Ordinal)).ToList();
    }

    public async Task<OAuthAuthorizationRecord?> FindValidGrantAsync(string authorizationId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(authorizationId);
        const string valid = OpenIddictConstants.Statuses.Valid;
        var rows = await QueryAsync(
            authorization => authorization.Id == authorizationId && authorization.Status == valid,
            cancellationToken);
        return rows.Count == 0 ? null : rows[0];
    }

    public Task<IReadOnlyList<OAuthAuthorizationRecord>> ListValidGrantsAsync(string applicationId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(applicationId);
        const string valid = OpenIddictConstants.Statuses.Valid;
        return QueryAsync(
            authorization => authorization.Application!.Id == applicationId && authorization.Status == valid,
            cancellationToken);
    }

    public async Task<IReadOnlyDictionary<string, OAuthClientRedirectUris>> FindRedirectUrisAsync(
        IReadOnlyCollection<string> clientIds,
        CancellationToken cancellationToken)
    {
        if (clientIds.Count == 0)
        {
            return new Dictionary<string, OAuthClientRedirectUris>(StringComparer.Ordinal);
        }

        var stored = await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking()
            .Where(application => clientIds.Contains(application.ClientId!))
            .Select(application => new { application.ClientId, application.RedirectUris, application.PostLogoutRedirectUris })
            .ToListAsync(cancellationToken);
        return stored.ToDictionary(
            application => application.ClientId!,
            application => new OAuthClientRedirectUris(
                ParseArray(application.RedirectUris),
                ParseArray(application.PostLogoutRedirectUris)),
            StringComparer.Ordinal);
    }

    private async Task<IReadOnlyList<OAuthAuthorizationRecord>> QueryAsync(
        Expression<Func<OpenIddictEntityFrameworkCoreAuthorization, bool>> filter,
        CancellationToken cancellationToken)
    {
        var rows = await db.Set<OpenIddictEntityFrameworkCoreAuthorization>()
            .AsNoTracking()
            .Where(filter)
            .Select(authorization => new
            {
                authorization.Id,
                authorization.Subject,
                authorization.Scopes,
                authorization.Properties,
                authorization.CreationDate,
                ClientId = authorization.Application == null ? null : authorization.Application.ClientId,
                ClientName = authorization.Application == null ? null : authorization.Application.DisplayName,
                Settings = authorization.Application == null ? null : authorization.Application.Settings,
            })
            .ToListAsync(cancellationToken);
        return rows.Select(row => OAuthAuthorizationRecord.FromStore(
                row.Id,
                row.Subject,
                ParseArray(row.Scopes),
                ParseObject(row.Properties),
                row.ClientId,
                row.ClientName,
                row.ClientId is null ? null : ParseSettings(row.Settings),
                row.CreationDate is { } created ? new DateTimeOffset(DateTime.SpecifyKind(created, DateTimeKind.Utc)) : null))
            .ToList();
    }

    private static Dictionary<string, JsonElement> ParseObject(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static Dictionary<string, string> ParseSettings(string? json)
        => ParseObject(json)
            .Where(pair => pair.Value.ValueKind == JsonValueKind.String)
            .ToDictionary(pair => pair.Key, pair => pair.Value.GetString()!, StringComparer.Ordinal);

    private static string[] ParseArray(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<string[]>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}

/// <summary>
/// Defers events while the server's <c>DbContext</c> has a transaction open, through the <see cref="OAuthEventTransactions"/>
/// interceptor on that context.
/// </summary>
internal sealed class EntityFrameworkOAuthServerEventTransactions<TContext>(TContext db, OAuthEventTransactions transactions)
    : IOAuthServerEventTransactions
    where TContext : DbContext
{
    public bool TryDefer(Func<CancellationToken, ValueTask> publish)
    {
        if (db.Database.CurrentTransaction is not { } transaction)
        {
            return false;
        }

        transactions.Defer(transaction.GetDbTransaction(), publish);
        return true;
    }
}

/// <summary>
/// OpenIddict's EF Core store marks a failed entry unchanged, but the context still tracks the values the write set,
/// with a concurrency token the database never stored. Reloads the entry, or detaches it when the row was deleted.
/// </summary>
internal sealed class EntityFrameworkOAuthAuthorizationRefresher<TContext>(TContext db) : IOAuthAuthorizationRefresher
    where TContext : DbContext
{
    public async ValueTask RefreshAsync(object authorization, CancellationToken cancellationToken)
    {
        var entry = db.Entry(authorization);
        if (entry.State == EntityState.Detached)
        {
            return;
        }

        if (await entry.GetDatabaseValuesAsync(cancellationToken) is { } stored)
        {
            entry.OriginalValues.SetValues(stored);
            entry.CurrentValues.SetValues(stored);
            entry.State = EntityState.Unchanged;
        }
        else
        {
            // Deleted meanwhile.
            entry.State = EntityState.Detached;
        }
    }
}

/// <summary>
/// Holds the events raised while a DbContext has a transaction open, and publishes them when EF Core reports the commit,
/// or drops them on rollback or a failed commit. Added to the server's DbContext as an interceptor. Keyed by the
/// transaction, which is never reused, so events of a transaction disposed without commit or rollback are simply
/// collected with it, even when the DbContext itself is pooled.
/// </summary>
internal sealed partial class OAuthEventTransactions(ILogger<OAuthEventTransactions> logger) : DbTransactionInterceptor
{
    private readonly ConditionalWeakTable<DbTransaction, List<Func<CancellationToken, ValueTask>>> _pending = new();

    public void Defer(DbTransaction transaction, Func<CancellationToken, ValueTask> publish)
    {
        var queue = _pending.GetOrCreateValue(transaction);
        lock (queue)
        {
            queue.Add(publish);
        }
    }

    public override void TransactionCommitted(DbTransaction transaction, TransactionEndEventData eventData)
        => PublishAsync(transaction).AsTask().GetAwaiter().GetResult();

    public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
        => PublishAsync(transaction).AsTask();

    public override void TransactionRolledBack(DbTransaction transaction, TransactionEndEventData eventData)
        => Drop(transaction);

    public override Task TransactionRolledBackAsync(DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
    {
        Drop(transaction);
        return Task.CompletedTask;
    }

    public override void TransactionFailed(DbTransaction transaction, TransactionErrorEventData eventData)
        => Drop(transaction);

    public override Task TransactionFailedAsync(DbTransaction transaction, TransactionErrorEventData eventData, CancellationToken cancellationToken = default)
    {
        Drop(transaction);
        return Task.CompletedTask;
    }

    private async ValueTask PublishAsync(DbTransaction transaction)
    {
        if (Take(transaction) is not { } queue)
        {
            return;
        }

        foreach (var publish in queue)
        {
            // The transaction has committed: what happened is final, so a cancelled request still gets its audit trail.
            await publish(CancellationToken.None);
        }
    }

    private void Drop(DbTransaction transaction)
    {
        if (Take(transaction) is { Count: > 0 } queue)
        {
            LogDropped(queue.Count);
        }
    }

    private List<Func<CancellationToken, ValueTask>>? Take(DbTransaction transaction)
    {
        if (!_pending.TryGetValue(transaction, out var queue))
        {
            return null;
        }

        _pending.Remove(transaction);
        lock (queue)
        {
            return [.. queue];
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "{Count} OAuth server event(s) were not raised because the host's transaction did not commit")]
    private partial void LogDropped(int count);
}
