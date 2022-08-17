namespace AuthEndpoints.SimpleJwt.Core.Services;
public interface IRefreshTokenGenerator<TUser>
{
    string GenerateRefreshToken(TUser user);
}
