using AuthEndpoints.Jwt;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Sessions;

internal static class ActiveSessionStore
{
    public static string? TrimUserAgent(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Length <= ActiveSession.MaxUserAgentLength ? value : value[..ActiveSession.MaxUserAgentLength];
    }

    public static DateTime AsUtc(DateTime value) =>
        value.Kind == DateTimeKind.Utc ? value : DateTime.SpecifyKind(value, DateTimeKind.Utc);
}

/// <summary>
/// The active-session rules over an <see cref="IActiveSessionStore"/>: the last-seen throttle, stamp filtering,
/// the validation cache, and, with JWT, ending a session's refresh tokens through <see cref="IRefreshTokenStore"/>.
/// </summary>
internal sealed class ActiveSessionService
{
    private readonly IActiveSessionStore _store;
    private readonly IRefreshTokenStore? _refreshTokens;
    private readonly TimeProvider _time;
    private readonly ActiveSessionOptions _options;
    private readonly ActiveSessionValidationCache? _cache;

    public ActiveSessionService(
        IActiveSessionStore store,
        TimeProvider time,
        IOptions<ActiveSessionOptions> options,
        ActiveSessionValidationCache? cache = null,
        IRefreshTokenStore? refreshTokens = null)
    {
        _store = store;
        _time = time;
        _options = options.Value;
        _cache = cache;
        _refreshTokens = refreshTokens;
    }

    private DateTime UtcNow => ActiveSessionStore.AsUtc(_time.GetUtcNow().UtcDateTime);

    public async Task CreateAsync(string id, string userId, string? userAgent, string securityStamp, DateTime expiresAt)
    {
        var now = UtcNow;
        await _store.TryCreateAsync(
            new ActiveSession
            {
                Id = id,
                UserId = userId,
                UserAgent = ActiveSessionStore.TrimUserAgent(userAgent),
                SecurityStamp = securityStamp,
                CreatedAt = now,
                LastSeenAt = now,
                ExpiresAt = ActiveSessionStore.AsUtc(expiresAt),
            },
            CancellationToken.None);
    }

    public Task<ActiveSession?> FindAsync(string id)
    {
        return _store.FindAsync(id, CancellationToken.None);
    }

    public async Task<bool> IsActiveAsync(string id)
    {
        var session = await _store.FindAsync(id, CancellationToken.None);
        return session is not null && IsLive(session, UtcNow);
    }

    public async Task TouchAsync(ActiveSession session, DateTime? expiresAt)
    {
        var now = UtcNow;
        if (now - ActiveSessionStore.AsUtc(session.LastSeenAt) < _options.LastSeenUpdateInterval)
        {
            return;
        }

        await _store.TouchAsync(session.Id, now, AsUtc(expiresAt), CancellationToken.None);
        session.LastSeenAt = now;
    }

    public Task UpdateStampAsync(string id, string securityStamp, DateTime? expiresAt)
    {
        return _store.UpdateStampAsync(id, securityStamp, UtcNow, AsUtc(expiresAt), CancellationToken.None);
    }

    public async Task EndAsync(IReadOnlyCollection<string> ids)
    {
        if (ids.Count == 0)
        {
            return;
        }

        _cache?.Remove(ids);
        var now = UtcNow;
        await _store.RevokeAsync(ids, now, CancellationToken.None);

        // Ending a JWT session revokes its refresh tokens so the next refresh fails.
        if (_refreshTokens is not null)
        {
            await _refreshTokens.RevokeSessionsAsync(ids, now, CancellationToken.None);
        }
    }

    public async Task<IReadOnlyList<ActiveSession>> ListAsync(string userId, string? currentStamp)
    {
        var sessions = await _store.ListActiveAsync(userId, UtcNow, CancellationToken.None);

        // Sessions from before the last stamp change are no longer usable; leave ending them to
        // the cookie check and refresh path so listing stays read-only.
        return sessions
            .Where(s => currentStamp is null || string.Equals(s.SecurityStamp, currentStamp, StringComparison.Ordinal))
            .OrderByDescending(s => s.LastSeenAt)
            .ToList();
    }

    public async Task<bool> RevokeAsync(string userId, string id)
    {
        var session = await _store.FindAsync(id, CancellationToken.None);
        if (session is null
            || !string.Equals(session.UserId, userId, StringComparison.Ordinal)
            || !IsLive(session, UtcNow))
        {
            return false;
        }

        await EndAsync([id]);
        return true;
    }

    public async Task<int> RevokeOthersAsync(string userId, string? currentId)
    {
        var ids = (await _store.ListUnrevokedIdsAsync(userId, CancellationToken.None))
            .Where(id => !string.Equals(id, currentId, StringComparison.Ordinal))
            .ToList();
        await EndAsync(ids);
        return ids.Count;
    }

    public Task<int> CleanupAsync()
    {
        _cache?.Sweep();
        return _store.DeleteEndedAsync(UtcNow, CancellationToken.None);
    }

    public Task SetTokenSessionAsync(string tokenId, string sessionId)
    {
        return _refreshTokens?.SetSessionAsync(tokenId, sessionId, CancellationToken.None) ?? Task.CompletedTask;
    }

    public async Task<string?> SessionIdForFamilyAsync(string familyId)
    {
        if (_refreshTokens is null)
        {
            return null;
        }

        var ids = await _refreshTokens.FindFamilySessionIdsAsync(familyId, CancellationToken.None);
        return ids.Count == 0 ? null : ids[0];
    }

    public async Task EndFamilyAsync(string familyId)
    {
        if (_refreshTokens is null)
        {
            return;
        }

        var ids = await _refreshTokens.FindFamilySessionIdsAsync(familyId, CancellationToken.None);
        await EndAsync(ids);
    }

    private static bool IsLive(ActiveSession session, DateTime now) =>
        session.RevokedAt == null && ActiveSessionStore.AsUtc(session.ExpiresAt) > now;

    private static DateTime? AsUtc(DateTime? value) => value is { } v ? ActiveSessionStore.AsUtc(v) : null;
}
