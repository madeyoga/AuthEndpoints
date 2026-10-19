using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Manages hashed refresh tokens with family-based reuse detection and an absolute family lifetime.
/// </summary>
public class RefreshTokenService<TContext> : IRefreshTokenService
    where TContext : DbContext
{
    private readonly TContext _db;
    private readonly TimeProvider _time;
    private readonly JwtSessionOptions _session;

    public RefreshTokenService(TContext db)
        : this(db, TimeProvider.System, Options.Create(new JwtSessionOptions()))
    {
    }

    public RefreshTokenService(TContext db, TimeProvider time, IOptions<JwtSessionOptions> sessionOptions)
    {
        _db = db;
        _time = time;
        _session = sessionOptions.Value;
    }

    public Task<RefreshToken?> GetRefreshTokenAsync(string rawToken)
    {
        var hash = HashToken(rawToken);
        return _db.Set<RefreshToken>().Where(t => t.TokenHash == hash).FirstOrDefaultAsync();
    }

    public async Task<RefreshToken?> RotateAsync(RefreshToken refreshToken, string securityStamp)
    {
        var now = UtcNow;
        var absoluteExpiresAt = AsUtc(refreshToken.AbsoluteExpiresAt);
        if (refreshToken.RevokedAt != null
            || AsUtc(refreshToken.ExpiresAt) <= now
            || absoluteExpiresAt <= now)
        {
            return null;
        }

        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var expiresAt = now.Add(_session.RefreshTokenLifetime);
        if (expiresAt > absoluteExpiresAt)
        {
            expiresAt = absoluteExpiresAt;
        }

        var successor = new RefreshToken
        {
            TokenHash = HashToken(rawToken),
            FamilyId = refreshToken.FamilyId,
            SecurityStamp = securityStamp,
            UserId = refreshToken.UserId,
            ExpiresAt = expiresAt,
            AbsoluteExpiresAt = absoluteExpiresAt,
            Token = rawToken
        };

        var lostRace = false;
        await using (var transaction = await _db.Database.BeginTransactionAsync())
        {
            var affected = await _db.Set<RefreshToken>()
                .Where(t => t.Id == refreshToken.Id && t.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(t => t.RevokedAt, now)
                    .SetProperty(t => t.ReplacedByTokenId, successor.Id));

            if (affected == 0)
            {
                await transaction.RollbackAsync();
                lostRace = true;
            }
            else
            {
                // ExecuteUpdate bypasses the change tracker. Align (or detach) the presented
                // entity so the upcoming SaveChanges cannot write RevokedAt=null back over the CAS.
                refreshToken.RevokedAt = now;
                refreshToken.ReplacedByTokenId = successor.Id;
                var entry = _db.Entry(refreshToken);
                if (entry.State != EntityState.Detached)
                {
                    entry.State = EntityState.Detached;
                }

                _db.Add(successor);
                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
            }
        }

        if (lostRace)
        {
            await RevokeFamilyAsync(refreshToken.FamilyId);
            return null;
        }

        return successor;
    }

    public Task RevokeAsync(RefreshToken refreshToken)
    {
        refreshToken.RevokedAt = UtcNow;
        _db.Update(refreshToken);
        return _db.SaveChangesAsync();
    }

    public async Task RevokeFamilyAsync(string familyId)
    {
        var now = UtcNow;
        // ExecuteUpdate does not touch the change tracker. Detach this family's tracked rows
        // so a later SaveChanges cannot write RevokedAt = null back over the update.
        foreach (var entry in _db.ChangeTracker.Entries<RefreshToken>().ToList())
        {
            if (!string.Equals(entry.Entity.FamilyId, familyId, StringComparison.Ordinal))
            {
                continue;
            }

            if (entry.Entity.RevokedAt == null)
            {
                entry.Entity.RevokedAt = now;
            }

            entry.State = EntityState.Detached;
        }

        await _db.Set<RefreshToken>()
            .Where(t => t.FamilyId == familyId && t.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.RevokedAt, now));
    }

    public async Task<RefreshToken> CreateAsync(string userId, string securityStamp, string? familyId = null)
    {
        var now = UtcNow;
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var absoluteExpiresAt = await ResolveAbsoluteExpiresAtAsync(familyId, now);
        var expiresAt = now.Add(_session.RefreshTokenLifetime);
        if (expiresAt > absoluteExpiresAt)
        {
            expiresAt = absoluteExpiresAt;
        }

        var newRefreshToken = new RefreshToken
        {
            TokenHash = HashToken(rawToken),
            FamilyId = familyId ?? Guid.NewGuid().ToString(),
            SecurityStamp = securityStamp,
            UserId = userId,
            ExpiresAt = expiresAt,
            AbsoluteExpiresAt = absoluteExpiresAt,
            Token = rawToken
        };

        _db.Add(newRefreshToken);
        await _db.SaveChangesAsync();
        return newRefreshToken;
    }

    public bool IsValid(RefreshToken refreshToken)
    {
        var now = UtcNow;
        return AsUtc(refreshToken.ExpiresAt) > now
            && AsUtc(refreshToken.AbsoluteExpiresAt) > now
            && refreshToken.RevokedAt == null;
    }

    internal static string HashToken(string rawToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes);
    }

    private async Task<DateTime> ResolveAbsoluteExpiresAtAsync(string? familyId, DateTime now)
    {
        if (string.IsNullOrEmpty(familyId))
        {
            return now.Add(_session.AbsoluteLifetime);
        }

        var existing = await _db.Set<RefreshToken>()
            .AsNoTracking()
            .Where(t => t.FamilyId == familyId)
            .Select(t => (DateTime?)t.AbsoluteExpiresAt)
            .FirstOrDefaultAsync();

        return existing is { } found ? AsUtc(found) : now.Add(_session.AbsoluteLifetime);
    }

    private DateTime UtcNow => AsUtc(_time.GetUtcNow().UtcDateTime);

    private static DateTime AsUtc(DateTime value) =>
        value.Kind == DateTimeKind.Utc ? value : DateTime.SpecifyKind(value, DateTimeKind.Utc);
}
