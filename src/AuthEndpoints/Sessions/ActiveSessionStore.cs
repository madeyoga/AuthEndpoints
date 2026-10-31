using AuthEndpoints.Jwt;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Sessions;

internal interface IActiveSessionStore
{
    Task CreateAsync(string id, string userId, string? userAgent, string securityStamp, DateTime expiresAt);

    Task<ActiveSession?> FindAsync(string id);

    Task<bool> IsActiveAsync(string id);

    Task TouchAsync(ActiveSession session, DateTime? expiresAt);

    Task UpdateStampAsync(string id, string securityStamp, DateTime? expiresAt);

    Task EndAsync(IReadOnlyCollection<string> ids);

    Task<IReadOnlyList<ActiveSession>> ListAsync(string userId, string? currentStamp);

    Task<bool> RevokeAsync(string userId, string id);

    Task<int> RevokeOthersAsync(string userId, string? currentId);

    Task<int> CleanupAsync();

    Task<string?> SessionIdForTokenAsync(string tokenId);

    Task SetTokenSessionAsync(string tokenId, string sessionId);

    Task<string?> SessionIdForFamilyAsync(string familyId);

    Task EndFamilyAsync(string familyId);
}

internal static class ActiveSessionStore
{
    public const int MaxUserAgentLength = 512;

    public static string? TrimUserAgent(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Length <= MaxUserAgentLength ? value : value[..MaxUserAgentLength];
    }

    public static DateTime AsUtc(DateTime value) =>
        value.Kind == DateTimeKind.Utc ? value : DateTime.SpecifyKind(value, DateTimeKind.Utc);
}

internal sealed class ActiveSessionStore<TContext> : IActiveSessionStore
    where TContext : DbContext
{
    private const string SessionIdProperty = ActiveSessionModelBuilderExtensions.RefreshTokenSessionIdProperty;

    private readonly TContext _db;
    private readonly TimeProvider _time;
    private readonly ActiveSessionOptions _options;
    private readonly ActiveSessionValidationCache? _cache;

    public ActiveSessionStore(
        TContext db,
        TimeProvider time,
        IOptions<ActiveSessionOptions> options,
        ActiveSessionValidationCache? cache = null)
    {
        _db = db;
        _time = time;
        _options = options.Value;
        _cache = cache;
    }

    private DateTime UtcNow => ActiveSessionStore.AsUtc(_time.GetUtcNow().UtcDateTime);

    private DbSet<ActiveSession> Sessions => _db.Set<ActiveSession>();

    private bool TracksRefreshTokens =>
        _db.Model.FindEntityType(typeof(RefreshToken))?.FindProperty(SessionIdProperty) is not null;

    public async Task CreateAsync(string id, string userId, string? userAgent, string securityStamp, DateTime expiresAt)
    {
        if (await Sessions.AsNoTracking().AnyAsync(s => s.Id == id))
        {
            return;
        }

        var now = UtcNow;
        var session = new ActiveSession
        {
            Id = id,
            UserId = userId,
            UserAgent = ActiveSessionStore.TrimUserAgent(userAgent),
            SecurityStamp = securityStamp,
            CreatedAt = now,
            LastSeenAt = now,
            ExpiresAt = ActiveSessionStore.AsUtc(expiresAt),
        };
        Sessions.Add(session);
        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateException)
        {
            // A concurrent request may have created the same session first; keep theirs.
            if (!await ExistsAfterConflictAsync(session))
            {
                throw;
            }
        }
    }

    private async Task<bool> ExistsAfterConflictAsync(ActiveSession session)
    {
        _db.Entry(session).State = EntityState.Detached;
        return await Sessions.AsNoTracking().AnyAsync(s => s.Id == session.Id);
    }

    public Task<ActiveSession?> FindAsync(string id)
    {
        return Sessions.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id);
    }

    public async Task<bool> IsActiveAsync(string id)
    {
        var now = UtcNow;
        return await Sessions.AsNoTracking()
            .AnyAsync(s => s.Id == id && s.RevokedAt == null && s.ExpiresAt > now);
    }

    public async Task TouchAsync(ActiveSession session, DateTime? expiresAt)
    {
        var now = UtcNow;
        if (now - ActiveSessionStore.AsUtc(session.LastSeenAt) < _options.LastSeenUpdateInterval)
        {
            return;
        }

        if (expiresAt is { } expires)
        {
            var utc = ActiveSessionStore.AsUtc(expires);
            await Sessions
                .Where(s => s.Id == session.Id && s.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(s => s.LastSeenAt, now)
                    .SetProperty(s => s.ExpiresAt, utc));
        }
        else
        {
            await Sessions
                .Where(s => s.Id == session.Id && s.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters.SetProperty(s => s.LastSeenAt, now));
        }

        session.LastSeenAt = now;
    }

    public async Task UpdateStampAsync(string id, string securityStamp, DateTime? expiresAt)
    {
        var now = UtcNow;
        if (expiresAt is { } expires)
        {
            var utc = ActiveSessionStore.AsUtc(expires);
            await Sessions
                .Where(s => s.Id == id && s.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(s => s.SecurityStamp, securityStamp)
                    .SetProperty(s => s.LastSeenAt, now)
                    .SetProperty(s => s.ExpiresAt, utc));
            return;
        }

        await Sessions
            .Where(s => s.Id == id && s.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(s => s.SecurityStamp, securityStamp)
                .SetProperty(s => s.LastSeenAt, now));
    }

    public async Task EndAsync(IReadOnlyCollection<string> ids)
    {
        if (ids.Count == 0)
        {
            return;
        }

        _cache?.Remove(ids);
        var now = UtcNow;
        await Sessions
            .Where(s => ids.Contains(s.Id) && s.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(s => s.RevokedAt, now));

        if (!TracksRefreshTokens)
        {
            return;
        }

        // Ending a JWT session revokes its refresh-token family so the next refresh fails.
        foreach (var entry in _db.ChangeTracker.Entries<RefreshToken>().ToList())
        {
            var sessionId = entry.Property<string?>(SessionIdProperty).CurrentValue;
            if (sessionId is not null && ids.Contains(sessionId))
            {
                entry.State = EntityState.Detached;
            }
        }

        await _db.Set<RefreshToken>()
            .Where(t => ids.Contains(EF.Property<string>(t, SessionIdProperty)) && t.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.RevokedAt, now));
    }

    public async Task<IReadOnlyList<ActiveSession>> ListAsync(string userId, string? currentStamp)
    {
        var now = UtcNow;
        var sessions = await Sessions.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
            .ToListAsync();

        // Sessions from before the last stamp change are no longer usable; leave ending them to
        // the cookie check and refresh path so listing stays read-only.
        return sessions
            .Where(s => currentStamp is null || string.Equals(s.SecurityStamp, currentStamp, StringComparison.Ordinal))
            .OrderByDescending(s => s.LastSeenAt)
            .ToList();
    }

    public async Task<bool> RevokeAsync(string userId, string id)
    {
        var now = UtcNow;
        var owned = await Sessions.AsNoTracking()
            .AnyAsync(s => s.Id == id && s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now);
        if (!owned)
        {
            return false;
        }

        await EndAsync([id]);
        return true;
    }

    public async Task<int> RevokeOthersAsync(string userId, string? currentId)
    {
        var ids = await Sessions.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.Id != currentId)
            .Select(s => s.Id)
            .ToListAsync();
        await EndAsync(ids);
        return ids.Count;
    }

    public async Task<int> CleanupAsync()
    {
        _cache?.Sweep();
        var now = UtcNow;
        return await Sessions
            .Where(s => s.RevokedAt != null || s.ExpiresAt <= now)
            .ExecuteDeleteAsync();
    }

    public async Task<string?> SessionIdForTokenAsync(string tokenId)
    {
        if (!TracksRefreshTokens)
        {
            return null;
        }

        return await _db.Set<RefreshToken>().AsNoTracking()
            .Where(t => t.Id == tokenId)
            .Select(t => EF.Property<string?>(t, SessionIdProperty))
            .FirstOrDefaultAsync();
    }

    public async Task SetTokenSessionAsync(string tokenId, string sessionId)
    {
        if (!TracksRefreshTokens)
        {
            return;
        }

        await _db.Set<RefreshToken>()
            .Where(t => t.Id == tokenId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => EF.Property<string?>(t, SessionIdProperty), sessionId));

        var tracked = _db.ChangeTracker.Entries<RefreshToken>().FirstOrDefault(e => e.Entity.Id == tokenId);
        if (tracked is not null)
        {
            tracked.Property<string?>(SessionIdProperty).CurrentValue = sessionId;
            tracked.Property<string?>(SessionIdProperty).OriginalValue = sessionId;
        }
    }

    public async Task<string?> SessionIdForFamilyAsync(string familyId)
    {
        if (!TracksRefreshTokens)
        {
            return null;
        }

        return await _db.Set<RefreshToken>().AsNoTracking()
            .Where(t => t.FamilyId == familyId && EF.Property<string?>(t, SessionIdProperty) != null)
            .Select(t => EF.Property<string?>(t, SessionIdProperty))
            .FirstOrDefaultAsync();
    }

    public async Task EndFamilyAsync(string familyId)
    {
        if (!TracksRefreshTokens)
        {
            return;
        }

        var ids = await _db.Set<RefreshToken>().AsNoTracking()
            .Where(t => t.FamilyId == familyId && EF.Property<string?>(t, SessionIdProperty) != null)
            .Select(t => EF.Property<string>(t, SessionIdProperty))
            .Distinct()
            .ToListAsync();
        await EndAsync(ids);
    }
}
