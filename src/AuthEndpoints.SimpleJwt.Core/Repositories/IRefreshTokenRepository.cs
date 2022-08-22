using AuthEndpoints.SimpleJwt.Core.Models;

namespace AuthEndpoints.SimpleJwt.Core;

/// <summary>
/// Implements <see cref="IRefreshTokenRepository"/> to define your Refresh token repository
/// </summary>
public interface IRefreshTokenRepository
{
    Task AddAsync(RefreshToken refreshToken);
    Task<RefreshToken?> GetByIdAsync(int id);
    Task<RefreshToken?> GetByTokenAsync(string token);
    Task<int> SaveChangesAsync();
}
