using AuthEndpoints.Jwt;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Sessions;

/// <summary>
/// EF Core <see cref="IActiveSessionStore"/>. Rows are read untracked and updated with conditional statements, and
/// nothing stays tracked after a call.
/// </summary>
internal sealed class ActiveSessionStore<TContext> : IActiveSessionStore
    where TContext : DbContext
{
    private readonly TContext _db;

    public ActiveSessionStore(TContext db)
    {
        if (db.Model.FindEntityType(typeof(ActiveSession)) is null)
        {
            throw new InvalidOperationException(
                $"AddActiveSessions needs the session table. Call modelBuilder.UseActiveSessions() in {typeof(TContext).Name}.OnModelCreating.");
        }

        if (db.Model.FindEntityType(typeof(RefreshToken)) is { } refreshTokens
            && refreshTokens.FindProperty(nameof(RefreshToken.SessionId)) is null)
        {
            throw new InvalidOperationException(
                $"Active sessions with JWT need the refresh-token SessionId column. Call modelBuilder.UseRefreshToken() before modelBuilder.UseActiveSessions() in {typeof(TContext).Name}.OnModelCreating.");
        }

        _db = db;
    }

    private DbSet<ActiveSession> Sessions => _db.Set<ActiveSession>();

    public async Task<bool> TryCreateAsync(ActiveSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (await Sessions.AsNoTracking().AnyAsync(s => s.Id == session.Id, cancellationToken))
        {
            return false;
        }

        Sessions.Add(session);
        try
        {
            await _db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException)
        {
            // A concurrent request may have created the same session first; keep theirs.
            Detach(session);
            if (await Sessions.AsNoTracking().AnyAsync(s => s.Id == session.Id, cancellationToken))
            {
                return false;
            }

            throw;
        }
        finally
        {
            Detach(session);
        }
    }

    public Task<ActiveSession?> FindAsync(string id, CancellationToken cancellationToken)
    {
        return Sessions.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, cancellationToken);
    }

    public async Task TouchAsync(string id, DateTime lastSeenAt, DateTime? expiresAt, CancellationToken cancellationToken)
    {
        if (expiresAt is { } expires)
        {
            await Sessions
                .Where(s => s.Id == id && s.RevokedAt == null)
                .ExecuteUpdateAsync(
                    setters => setters
                        .SetProperty(s => s.LastSeenAt, lastSeenAt)
                        .SetProperty(s => s.ExpiresAt, expires),
                    cancellationToken);
            return;
        }

        await Sessions
            .Where(s => s.Id == id && s.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(s => s.LastSeenAt, lastSeenAt), cancellationToken);
    }

    public async Task UpdateStampAsync(
        string id,
        string securityStamp,
        DateTime lastSeenAt,
        DateTime? expiresAt,
        CancellationToken cancellationToken)
    {
        if (expiresAt is { } expires)
        {
            await Sessions
                .Where(s => s.Id == id && s.RevokedAt == null)
                .ExecuteUpdateAsync(
                    setters => setters
                        .SetProperty(s => s.SecurityStamp, securityStamp)
                        .SetProperty(s => s.LastSeenAt, lastSeenAt)
                        .SetProperty(s => s.ExpiresAt, expires),
                    cancellationToken);
            return;
        }

        await Sessions
            .Where(s => s.Id == id && s.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(s => s.SecurityStamp, securityStamp)
                    .SetProperty(s => s.LastSeenAt, lastSeenAt),
                cancellationToken);
    }

    public async Task RevokeAsync(IReadOnlyCollection<string> ids, DateTime revokedAt, CancellationToken cancellationToken)
    {
        if (ids.Count == 0)
        {
            return;
        }

        await Sessions
            .Where(s => ids.Contains(s.Id) && s.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(s => s.RevokedAt, revokedAt), cancellationToken);
    }

    public async Task<IReadOnlyList<ActiveSession>> ListActiveAsync(
        string userId,
        DateTime now,
        CancellationToken cancellationToken)
    {
        return await Sessions.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<string>> ListUnrevokedIdsAsync(string userId, CancellationToken cancellationToken)
    {
        return await Sessions.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null)
            .Select(s => s.Id)
            .ToListAsync(cancellationToken);
    }

    public Task<int> DeleteEndedAsync(DateTime now, CancellationToken cancellationToken)
    {
        return Sessions
            .Where(s => s.RevokedAt != null || s.ExpiresAt <= now)
            .ExecuteDeleteAsync(cancellationToken);
    }

    private void Detach(ActiveSession session)
    {
        var entry = _db.Entry(session);
        if (entry.State != EntityState.Detached)
        {
            entry.State = EntityState.Detached;
        }
    }
}
