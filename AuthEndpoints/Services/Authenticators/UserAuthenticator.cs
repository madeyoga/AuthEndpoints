namespace AuthEndpoints.Services.Authenticators;

using AuthEndpoints.Models.Responses;
using AuthEndpoints.Services.TokenGenerators;

public class UserAuthenticator<TUser> : IAuthenticator<TUser, AuthenticatedJwtResponse>
    where TUser : class
{
    private readonly ITokenGenerator<TUser> accessTokenGenerator;
    private readonly ITokenGenerator<TUser> refreshTokenGenerator;

    public UserAuthenticator(
        IAccessTokenGenerator<TUser> accessTokenGenerator,
        IRefreshTokenGenerator<TUser> refreshTokenGenerator)
    {
        this.accessTokenGenerator = accessTokenGenerator;
        this.refreshTokenGenerator = refreshTokenGenerator;
    }

    public Task<AuthenticatedJwtResponse> Authenticate(TUser user)
    {
        string accessToken = accessTokenGenerator.GenerateToken(user);
        string refreshToken = refreshTokenGenerator.GenerateToken(user);

        return Task.FromResult(new AuthenticatedJwtResponse()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
        });
    }
}
