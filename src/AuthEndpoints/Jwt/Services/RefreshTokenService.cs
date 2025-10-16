using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Use this class to manage refresh tokens
/// </summary>
public class RefreshTokenService<TContext> : IRefreshTokenService
    where TContext : DbContext
{
    private readonly TContext _db;

    public RefreshTokenService(TContext db)
    {
        _db = db;
    }

    public Task<RefreshToken?> GetRefreshTokenAsync(string token)
    {
        return _db.Set<RefreshToken>().Where(t => t.Token == token).FirstOrDefaultAsync();
    }

    public async Task<RefreshToken> RotateAsync(RefreshToken refreshToken)
    {
        await RevokeAsync(refreshToken);

        return await CreateAsync(refreshToken.UserId);
    }

    public Task RevokeAsync(RefreshToken refreshToken)
    {
        refreshToken.RevokedAt = DateTime.UtcNow;
        _db.Update(refreshToken);
        return _db.SaveChangesAsync();
    }

    public async Task<RefreshToken> CreateAsync(string userId)
    {
        var newRefreshToken = new RefreshToken
        {
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            UserId = userId,
            ExpiresAt = DateTime.UtcNow.AddDays(14)
        };

        _db.Add(newRefreshToken);

        await _db.SaveChangesAsync();

        return newRefreshToken;
    }
    
    public bool IsValid(RefreshToken refreshToken)
    {
        return refreshToken.ExpiresAt > DateTime.UtcNow && refreshToken.RevokedAt == null;
    }
}
