using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Jwt;

/// <summary>
/// EF Core <see cref="IRefreshTokenStore"/>. Rows are read untracked and written with conditional statements, and nothing
/// stays tracked after a call, so a later <c>SaveChanges</c> on the shared context cannot write a stale row back.
/// <see cref="RefreshToken.SessionId"/> is stored only when the model maps it (<c>UseActiveSessions</c>).
/// </summary>
internal sealed class RefreshTokenStore<TContext> : IRefreshTokenStore
    where TContext : DbContext
{
    private readonly TContext _db;

    public RefreshTokenStore(TContext db)
    {
        _db = db;
    }

    private DbSet<RefreshToken> Tokens => _db.Set<RefreshToken>();

    private bool SessionIdMapped =>
        _db.Model.FindEntityType(typeof(RefreshToken))?.FindProperty(nameof(RefreshToken.SessionId)) is not null;

    public Task<RefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken)
    {
        return Tokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == tokenHash, cancellationToken);
    }

    public async Task CreateAsync(RefreshToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        Tokens.Add(token);
        try
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
        finally
        {
            Detach(token);
        }
    }

    public async Task<bool> TryRotateAsync(
        string presentedId,
        RefreshToken successor,
        DateTime revokedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(successor);
        await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken);
        var affected = await Tokens
            .Where(t => t.Id == presentedId && t.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(t => t.RevokedAt, revokedAt)
                    .SetProperty(t => t.ReplacedByTokenId, successor.Id),
                cancellationToken);
        if (affected == 0)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        DetachTracked(t => t.Id == presentedId);
        Tokens.Add(successor);
        try
        {
            await _db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            Detach(successor);
        }

        return true;
    }

    public async Task RevokeAsync(string id, DateTime revokedAt, CancellationToken cancellationToken)
    {
        DetachTracked(t => t.Id == id);
        await Tokens
            .Where(t => t.Id == id && t.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.RevokedAt, revokedAt), cancellationToken);
    }

    public async Task RevokeFamilyAsync(string familyId, DateTime revokedAt, CancellationToken cancellationToken)
    {
        DetachTracked(t => string.Equals(t.FamilyId, familyId, StringComparison.Ordinal));
        await Tokens
            .Where(t => t.FamilyId == familyId && t.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.RevokedAt, revokedAt), cancellationToken);
    }

    public Task<DateTime?> FindFamilyAbsoluteExpiresAtAsync(string familyId, CancellationToken cancellationToken)
    {
        return Tokens.AsNoTracking()
            .Where(t => t.FamilyId == familyId)
            .Select(t => (DateTime?)t.AbsoluteExpiresAt)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task SetSessionAsync(string tokenId, string sessionId, CancellationToken cancellationToken)
    {
        if (!SessionIdMapped)
        {
            return;
        }

        DetachTracked(t => t.Id == tokenId);
        await Tokens
            .Where(t => t.Id == tokenId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.SessionId, sessionId), cancellationToken);
    }

    public async Task<IReadOnlyList<string>> FindFamilySessionIdsAsync(string familyId, CancellationToken cancellationToken)
    {
        if (!SessionIdMapped)
        {
            return [];
        }

        return await Tokens.AsNoTracking()
            .Where(t => t.FamilyId == familyId && t.SessionId != null)
            .Select(t => t.SessionId!)
            .Distinct()
            .ToListAsync(cancellationToken);
    }

    public async Task RevokeSessionsAsync(
        IReadOnlyCollection<string> sessionIds,
        DateTime revokedAt,
        CancellationToken cancellationToken)
    {
        if (sessionIds.Count == 0 || !SessionIdMapped)
        {
            return;
        }

        DetachTracked(t => t.SessionId != null && sessionIds.Contains(t.SessionId));
        await Tokens
            .Where(t => t.SessionId != null && sessionIds.Contains(t.SessionId) && t.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.RevokedAt, revokedAt), cancellationToken);
    }

    // ExecuteUpdate bypasses the change tracker. Detach matching rows that a caller attached to this context,
    // so a later SaveChanges cannot write their old values back over the update.
    private void DetachTracked(Func<RefreshToken, bool> match)
    {
        foreach (var entry in _db.ChangeTracker.Entries<RefreshToken>().ToList())
        {
            if (match(entry.Entity))
            {
                entry.State = EntityState.Detached;
            }
        }
    }

    private void Detach(RefreshToken token)
    {
        var entry = _db.Entry(token);
        if (entry.State != EntityState.Detached)
        {
            entry.State = EntityState.Detached;
        }
    }
}
