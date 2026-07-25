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

    public async Task<RefreshToken> RotateAsync(RefreshToken refreshToken, string securityStamp)
    {
        var successor = await CreateAsync(refreshToken.UserId, securityStamp, refreshToken.FamilyId);

        refreshToken.RevokedAt = DateTime.UtcNow;
        refreshToken.ReplacedByTokenId = successor.Id;
        _db.Update(refreshToken);
        await _db.SaveChangesAsync();

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
