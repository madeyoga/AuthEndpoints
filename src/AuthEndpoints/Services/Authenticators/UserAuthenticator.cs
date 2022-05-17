namespace AuthEndpoints.Services;

using AuthEndpoints.Models;

/// <summary>
/// Default user authenticator. Use this class to authenticate a user
/// </summary>
/// <typeparam name="TUser"></typeparam>
/// <typeparam name="TResponse"></typeparam>
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

    /// <summary>
    /// Authenticat a user
    /// </summary>
    /// <param name="user"></param>
    /// <returns>An instance of <see cref="AuthenticatedJwtResponse"/> that contain an access token and a refresh token</returns>
    public Task<AuthenticatedJwtResponse> Authenticate(TUser user)
    {
        string accessToken = accessTokenGenerator.Generate(user);
        string refreshToken = refreshTokenGenerator.Generate(user);

        return Task.FromResult(new AuthenticatedJwtResponse()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
        });
    }
}
