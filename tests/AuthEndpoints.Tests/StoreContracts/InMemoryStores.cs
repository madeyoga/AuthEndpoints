using AuthEndpoints.EmailCode;
using AuthEndpoints.Jwt;
using AuthEndpoints.Sessions;

namespace AuthEndpoints.Tests.StoreContracts;

// Test-only stores with no EF Core behind them (#410). They run the same store contracts as the EF Core stores, which
// shows the contracts can be met without a database, and they back the endpoint tests that run without EF Core stores.
// One lock per store makes each method atomic. Rows are copied in and out, as a database would, so a caller can never
// change a stored row through a reference it kept.

internal sealed class InMemoryEmailCodeStore : IEmailCodeStore
{
    private readonly object _gate = new();
    private readonly List<EmailCodeEntry> _rows = [];

    public Task<EmailCodeIssueStatus> IssueAsync(EmailCodeEntry entry, EmailCodeIssueRules rules, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var mine = _rows.Where(e => e.EmailHash == entry.EmailHash && e.Purpose == entry.Purpose).ToList();
            if (rules.CooldownSince is { } since && mine.Any(e => e.CreatedAt > since))
            {
                return Task.FromResult(EmailCodeIssueStatus.Cooldown);
            }

            _rows.RemoveAll(e => e.EmailHash == entry.EmailHash && e.Purpose == entry.Purpose && e.ExpiresAt < rules.DeleteExpiredBefore);
            foreach (var row in mine.Where(e => IsLive(e, rules.Liveness, attemptReserved: false)))
            {
                row.SupersededAt = rules.Liveness.Now;
            }

            _rows.Add(Copy(entry));
            return Task.FromResult(EmailCodeIssueStatus.Issued);
        }
    }

    public Task<EmailCodeEntry?> FindLiveByEmailAsync(
        string emailHash,
        EmailCodeRowPurpose purpose,
        string? userId,
        EmailCodeLiveness liveness,
        CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var row = _rows
                .Where(e => e.EmailHash == emailHash && e.Purpose == purpose && IsLive(e, liveness, attemptReserved: false))
                .Where(e => userId is null || e.UserId == userId)
                .OrderByDescending(e => e.CreatedAt)
                .ThenByDescending(e => e.Id, StringComparer.Ordinal)
                .FirstOrDefault();
            return Task.FromResult(row is null ? null : Copy(row));
        }
    }

    public Task<EmailCodeEntry?> FindLiveByLinkTokenAsync(string linkTokenHash, EmailCodeLiveness liveness, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var row = _rows.FirstOrDefault(e => e.LinkTokenHash == linkTokenHash
                && e.Purpose == EmailCodeRowPurpose.SignIn
                && IsLive(e, liveness, attemptReserved: false));
            return Task.FromResult(row is null ? null : Copy(row));
        }
    }

    public Task<bool> TryReserveAttemptAsync(string id, EmailCodeLiveness liveness, CancellationToken cancellationToken)
        => Update(id, row => IsLive(row, liveness, attemptReserved: false), row => row.Attempts++);

    public Task<bool> TryReleaseAttemptAsync(string id, CancellationToken cancellationToken)
        => Update(id, row => row.ConsumedAt is null && row.Attempts > 0, row => row.Attempts--);

    public Task<bool> TryConsumeAsync(string id, EmailCodeLiveness liveness, bool attemptReserved, CancellationToken cancellationToken)
        => Update(id, row => IsLive(row, liveness, attemptReserved), row => row.ConsumedAt = liveness.Now);

    public Task<bool> TryUnconsumeAsync(string id, CancellationToken cancellationToken)
        => Update(id, row => row.ConsumedAt is not null, row => row.ConsumedAt = null);

    public Task<int> CountIssuedSinceAsync(string emailHash, EmailCodeRowPurpose purpose, DateTime since, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(_rows.Count(e => e.EmailHash == emailHash && e.Purpose == purpose && e.CreatedAt >= since));
        }
    }

    public IReadOnlyList<EmailCodeEntry> Snapshot()
    {
        lock (_gate)
        {
            return _rows.Select(Copy).ToList();
        }
    }

    private Task<bool> Update(string id, Func<EmailCodeEntry, bool> condition, Action<EmailCodeEntry> change)
    {
        lock (_gate)
        {
            var row = _rows.FirstOrDefault(e => e.Id == id);
            if (row is null || !condition(row))
            {
                return Task.FromResult(false);
            }

            change(row);
            return Task.FromResult(true);
        }
    }

    private static bool IsLive(EmailCodeEntry row, EmailCodeLiveness liveness, bool attemptReserved)
        => row.ConsumedAt is null
            && row.SupersededAt is null
            && (attemptReserved ? row.Attempts <= liveness.MaxAttempts : row.Attempts < liveness.MaxAttempts)
            && row.ExpiresAt > liveness.Now;

    private static EmailCodeEntry Copy(EmailCodeEntry row) => new()
    {
        Id = row.Id,
        EmailHash = row.EmailHash,
        Purpose = row.Purpose,
        UserId = row.UserId,
        CodeHash = row.CodeHash,
        LinkTokenHash = row.LinkTokenHash,
        SecurityStamp = row.SecurityStamp,
        SignupEmail = row.SignupEmail,
        CreatedAt = row.CreatedAt,
        ExpiresAt = row.ExpiresAt,
        Attempts = row.Attempts,
        ConsumedAt = row.ConsumedAt,
        SupersededAt = row.SupersededAt,
    };
}

internal sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly object _gate = new();
    private readonly List<RefreshToken> _rows = [];

    public Task<RefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var row = _rows.FirstOrDefault(t => t.TokenHash == tokenHash);
            return Task.FromResult(row is null ? null : Copy(row));
        }
    }

    public Task CreateAsync(RefreshToken token, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_rows.Any(t => t.Id == token.Id || t.TokenHash == token.TokenHash))
            {
                throw new InvalidOperationException("A token with that id or hash exists.");
            }

            _rows.Add(Copy(token));
        }

        return Task.CompletedTask;
    }

    public Task<bool> TryRotateAsync(string presentedId, RefreshToken successor, DateTime revokedAt, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var presented = _rows.FirstOrDefault(t => t.Id == presentedId);
            if (presented is null || presented.RevokedAt is not null)
            {
                return Task.FromResult(false);
            }

            presented.RevokedAt = revokedAt;
            presented.ReplacedByTokenId = successor.Id;
            _rows.Add(Copy(successor));
            return Task.FromResult(true);
        }
    }

    public Task RevokeAsync(string id, DateTime revokedAt, CancellationToken cancellationToken)
        => Revoke(t => t.Id == id, revokedAt);

    public Task RevokeFamilyAsync(string familyId, DateTime revokedAt, CancellationToken cancellationToken)
        => Revoke(t => t.FamilyId == familyId, revokedAt);

    public Task<DateTime?> FindFamilyAbsoluteExpiresAtAsync(string familyId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(_rows.FirstOrDefault(t => t.FamilyId == familyId)?.AbsoluteExpiresAt);
        }
    }

    public Task SetSessionAsync(string tokenId, string sessionId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_rows.FirstOrDefault(t => t.Id == tokenId) is { } row)
            {
                row.SessionId = sessionId;
            }
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<string>> FindFamilySessionIdsAsync(string familyId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            IReadOnlyList<string> ids = _rows
                .Where(t => t.FamilyId == familyId && t.SessionId is not null)
                .Select(t => t.SessionId!)
                .Distinct(StringComparer.Ordinal)
                .ToList();
            return Task.FromResult(ids);
        }
    }

    public Task RevokeSessionsAsync(IReadOnlyCollection<string> sessionIds, DateTime revokedAt, CancellationToken cancellationToken)
        => Revoke(t => t.SessionId is not null && sessionIds.Contains(t.SessionId), revokedAt);

    private Task Revoke(Func<RefreshToken, bool> match, DateTime revokedAt)
    {
        lock (_gate)
        {
            foreach (var row in _rows.Where(t => t.RevokedAt is null && match(t)))
            {
                row.RevokedAt = revokedAt;
            }
        }

        return Task.CompletedTask;
    }

    // Token is the raw value and is never stored.
    private static RefreshToken Copy(RefreshToken row) => new()
    {
        Id = row.Id,
        TokenHash = row.TokenHash,
        FamilyId = row.FamilyId,
        ReplacedByTokenId = row.ReplacedByTokenId,
        SecurityStamp = row.SecurityStamp,
        UserId = row.UserId,
        ExpiresAt = row.ExpiresAt,
        AbsoluteExpiresAt = row.AbsoluteExpiresAt,
        RevokedAt = row.RevokedAt,
        SessionId = row.SessionId,
    };
}

internal sealed class InMemoryActiveSessionStore : IActiveSessionStore
{
    private readonly object _gate = new();
    private readonly List<ActiveSession> _rows = [];

    public Task<bool> TryCreateAsync(ActiveSession session, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_rows.Any(s => s.Id == session.Id))
            {
                return Task.FromResult(false);
            }

            _rows.Add(Copy(session));
            return Task.FromResult(true);
        }
    }

    public Task<ActiveSession?> FindAsync(string id, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var row = _rows.FirstOrDefault(s => s.Id == id);
            return Task.FromResult(row is null ? null : Copy(row));
        }
    }

    public Task TouchAsync(string id, DateTime lastSeenAt, DateTime? expiresAt, CancellationToken cancellationToken)
        => Update(id, row =>
        {
            row.LastSeenAt = lastSeenAt;
            row.ExpiresAt = expiresAt ?? row.ExpiresAt;
        });

    public Task UpdateStampAsync(string id, string securityStamp, DateTime lastSeenAt, DateTime? expiresAt, CancellationToken cancellationToken)
        => Update(id, row =>
        {
            row.SecurityStamp = securityStamp;
            row.LastSeenAt = lastSeenAt;
            row.ExpiresAt = expiresAt ?? row.ExpiresAt;
        });

    public Task RevokeAsync(IReadOnlyCollection<string> ids, DateTime revokedAt, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            foreach (var row in _rows.Where(s => ids.Contains(s.Id) && s.RevokedAt is null))
            {
                row.RevokedAt = revokedAt;
            }
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<ActiveSession>> ListActiveAsync(string userId, DateTime now, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            IReadOnlyList<ActiveSession> rows = _rows
                .Where(s => s.UserId == userId && s.RevokedAt is null && s.ExpiresAt > now)
                .Select(Copy)
                .ToList();
            return Task.FromResult(rows);
        }
    }

    public Task<IReadOnlyList<string>> ListUnrevokedIdsAsync(string userId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            IReadOnlyList<string> ids = _rows.Where(s => s.UserId == userId && s.RevokedAt is null).Select(s => s.Id).ToList();
            return Task.FromResult(ids);
        }
    }

    public Task<int> DeleteEndedAsync(DateTime now, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(_rows.RemoveAll(s => s.RevokedAt is not null || s.ExpiresAt <= now));
        }
    }

    private Task Update(string id, Action<ActiveSession> change)
    {
        lock (_gate)
        {
            if (_rows.FirstOrDefault(s => s.Id == id && s.RevokedAt is null) is { } row)
            {
                change(row);
            }
        }

        return Task.CompletedTask;
    }

    private static ActiveSession Copy(ActiveSession row) => new()
    {
        Id = row.Id,
        UserId = row.UserId,
        UserAgent = row.UserAgent,
        SecurityStamp = row.SecurityStamp,
        CreatedAt = row.CreatedAt,
        LastSeenAt = row.LastSeenAt,
        ExpiresAt = row.ExpiresAt,
        RevokedAt = row.RevokedAt,
    };
}
