using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Manages hashed refresh tokens with family-based reuse detection.
/// </summary>
public class RefreshTokenService<TContext> : IRefreshTokenService
    where TContext : DbContext
{
    private readonly TContext _db;

    public RefreshTokenService(TContext db)
    {
        _db = db;
    }

    public Task<RefreshToken?> GetRefreshTokenAsync(string rawToken)
    {
        var hash = HashToken(rawToken);
        return _db.Set<RefreshToken>().Where(t => t.TokenHash == hash).FirstOrDefaultAsync();
    }

    public async Task<RefreshToken?> RotateAsync(RefreshToken refreshToken, string securityStamp)
    {
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var successor = new RefreshToken
        {
            TokenHash = HashToken(rawToken),
            FamilyId = refreshToken.FamilyId,
            SecurityStamp = securityStamp,
            UserId = refreshToken.UserId,
            ExpiresAt = DateTime.UtcNow.AddDays(14),
            Token = rawToken
        };

        var now = DateTime.UtcNow;

        await using var transaction = await _db.Database.BeginTransactionAsync();

        // Compare-and-swap: only one concurrent rotator can revoke a still-live token.
        var affected = await _db.Set<RefreshToken>()
            .Where(t => t.Id == refreshToken.Id && t.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(t => t.RevokedAt, now)
                .SetProperty(t => t.ReplacedByTokenId, successor.Id));

        if (affected == 0)
        {
            await transaction.RollbackAsync();
            return null;
        }

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
        return successor;
    }

    public Task RevokeAsync(RefreshToken refreshToken)
    {
        refreshToken.RevokedAt = DateTime.UtcNow;
        _db.Update(refreshToken);
        return _db.SaveChangesAsync();
    }

    public async Task RevokeFamilyAsync(string familyId)
    {
        var tokens = await _db.Set<RefreshToken>()
            .Where(t => t.FamilyId == familyId && t.RevokedAt == null)
            .ToListAsync();

        var now = DateTime.UtcNow;
        foreach (var token in tokens)
        {
            token.RevokedAt = now;
        }

        if (tokens.Count > 0)
        {
            _db.UpdateRange(tokens);
            await _db.SaveChangesAsync();
        }
    }

    public async Task<RefreshToken> CreateAsync(string userId, string securityStamp, string? familyId = null)
    {
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var newRefreshToken = new RefreshToken
        {
            TokenHash = HashToken(rawToken),
            FamilyId = familyId ?? Guid.NewGuid().ToString(),
            SecurityStamp = securityStamp,
            UserId = userId,
            ExpiresAt = DateTime.UtcNow.AddDays(14),
            Token = rawToken
        };

        _db.Add(newRefreshToken);
        await _db.SaveChangesAsync();
        return newRefreshToken;
    }

    public bool IsValid(RefreshToken refreshToken)
    {
        return refreshToken.ExpiresAt > DateTime.UtcNow && refreshToken.RevokedAt == null;
    }

    internal static string HashToken(string rawToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes);
    }
}
