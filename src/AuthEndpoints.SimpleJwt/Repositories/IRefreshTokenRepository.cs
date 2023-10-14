namespace AuthEndpoints.SimpleJwt;

/// <summary>
/// Implements <see cref="IRefreshTokenRepository"/> to define your Refresh token repository
/// </summary>
public interface IRefreshTokenRepository
{
    Task AddAsync(SimpleJwtRefreshToken refreshToken);
    Task<SimpleJwtRefreshToken?> GetByIdAsync(int id);
    Task<SimpleJwtRefreshToken?> GetByTokenAsync(string token);
    Task<int> SaveChangesAsync();
}
