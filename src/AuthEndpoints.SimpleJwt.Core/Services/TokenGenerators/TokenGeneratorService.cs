namespace AuthEndpoints.SimpleJwt.Core.Services;

public class TokenGeneratorService<TUser> : ITokenGeneratorService<TUser>
{
    protected readonly IAccessTokenGenerator<TUser> _accessTokenGenerator;
    protected readonly IRefreshTokenGenerator<TUser> _refreshTokenGenerator;

    public TokenGeneratorService(IAccessTokenGenerator<TUser> accessTokenGenerator, IRefreshTokenGenerator<TUser> refreshTokenGenerator)
    {
        _accessTokenGenerator = accessTokenGenerator;
        _refreshTokenGenerator = refreshTokenGenerator;
    }

    public string GenerateAccessToken(TUser user)
    {
        return _accessTokenGenerator.GenerateAccessToken(user);
    }

    public string GenerateRefreshToken(TUser user)
    {
        return _refreshTokenGenerator.GenerateRefreshToken(user);
    }
}
