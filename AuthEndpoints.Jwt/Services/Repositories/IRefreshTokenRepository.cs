namespace AuthEndpoints.Jwt.Services.Repositories;

public interface IRefreshTokenRepository<TUserKey, TRefreshToken> where TRefreshToken : class
{
    Task Create(TRefreshToken refreshToken);
    Task<TRefreshToken?> GetByToken(string token);
    Task Delete(Guid refreshTokenId);
    Task DeleteAll(TUserKey userId);
}
