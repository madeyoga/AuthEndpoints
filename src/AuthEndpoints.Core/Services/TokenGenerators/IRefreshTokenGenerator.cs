namespace AuthEndpoints.Core.Services;
public interface IRefreshTokenGenerator<TUser>
{
    string GenerateRefreshToken(TUser user);
}
