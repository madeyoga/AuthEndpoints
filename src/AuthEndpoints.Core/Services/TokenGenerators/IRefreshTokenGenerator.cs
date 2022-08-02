namespace AuthEndpoints.Services;
public interface IRefreshTokenGenerator<TUser>
{
    string GenerateRefreshToken(TUser user);
}
