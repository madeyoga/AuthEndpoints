namespace AuthEndpoints.Jwt;

public interface IRefreshTokenService
{
    Task<RefreshToken?> GetRefreshTokenAsync(string token);
    Task RevokeAsync(RefreshToken refreshToken);
    Task<RefreshToken> CreateAsync(string userId);
    Task<RefreshToken> RotateAsync(RefreshToken refreshToken);
    bool IsValid(RefreshToken refreshToken);
}
