namespace AuthEndpoints.Services;

using AuthEndpoints.Models;
using Microsoft.AspNetCore.Identity;

/// <summary>
/// Default user authenticator. Use this class to authenticate a user
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class UserAuthenticator<TUser> : IAuthenticator<TUser>
    where TUser : class
{
    private readonly ITokenGenerator<TUser> accessTokenGenerator;
    private readonly ITokenGenerator<TUser> refreshTokenGenerator;
    private readonly UserManager<TUser> userManager;

    public UserAuthenticator(IAccessTokenGenerator<TUser> accessTokenGenerator,
        IRefreshTokenGenerator<TUser> refreshTokenGenerator,
        UserManager<TUser> userManager)
    {
        this.accessTokenGenerator = accessTokenGenerator;
        this.refreshTokenGenerator = refreshTokenGenerator;
        this.userManager = userManager;
    }

    /// <summary>
    /// Use this method to verify a set of credentials. It takes credentials as argument, username and password for the default case.
    /// </summary>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <returns>An instance of TUser if credentials are valid</returns>
    public async Task<TUser?> Authenticate(string username, string password)
    {
        TUser user = await userManager.FindByNameAsync(username);

        if (user == null)
        {
            return null;
        }

        bool correctPassword = await userManager.CheckPasswordAsync(user, password);

        if (!correctPassword)
        {
            return null;
        }

        return user;
    }

    /// <summary>
    /// Use this method to get an access token and a refresh token for the given TUser
    /// </summary>
    /// <param name="user"></param>
    /// <returns>An instance of <see cref="AuthenticatedUserResponse"/>, containing an access token and a refresh token</returns>
    public Task<AuthenticatedUserResponse> Login(TUser user)
    {
        string accessToken = accessTokenGenerator.Generate(user);
        string refreshToken = refreshTokenGenerator.Generate(user);

        return Task.FromResult(new AuthenticatedUserResponse()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
        });
    }
}
