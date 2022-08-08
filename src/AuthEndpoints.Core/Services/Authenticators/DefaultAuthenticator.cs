using AuthEndpoints.Core.Contracts;
using AuthEndpoints.Core.Models;
using AuthEndpoints.Core.Repositories;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Core.Services;

/// <summary>
/// Default authenticator. 
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class DefaultAuthenticator<TUser> : IAuthenticator<TUser>
    where TUser : class
{
    private readonly UserManager<TUser> userManager;
    private readonly ITokenGeneratorService<TUser> tokenGenerator;
    private readonly IRefreshTokenRepository refreshTokenRepository;

    public DefaultAuthenticator(UserManager<TUser> userManager, ITokenGeneratorService<TUser> tokenGenerator, IRefreshTokenRepository refreshTokenRepository)
    {
        this.userManager = userManager;
        this.tokenGenerator = tokenGenerator;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    /// <summary>
    /// Use this method to verify a set of credentials. It takes credentials as argument, username and password for the default case.
    /// </summary>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <returns>An instance of TUser if credentials are valid</returns>
    public async Task<TUser?> Authenticate(string username, string password)
    {
        var user = await userManager.FindByNameAsync(username);

        if (user == null)
        {
            return null;
        }

        var correctPassword = await userManager.CheckPasswordAsync(user, password);

        if (!correctPassword)
        {
            return null;
        }

        return user;
    }

    /// <summary>
    /// Use this method to get an access Token and a refresh Token for the given TUser
    /// </summary>
    /// <param name="user"></param>
    /// <returns>An instance of <see cref="AuthenticatedUserResponse"/>, containing an access Token and a refresh Token</returns>
    public async Task<AuthenticatedUserResponse> Login(TUser user)
    {
        var accessToken = tokenGenerator.GenerateAccessToken(user);
        var refreshToken = tokenGenerator.GenerateRefreshToken(user);
        await refreshTokenRepository.AddAsync(new RefreshToken
        {
            Token = refreshToken,
        });
        await refreshTokenRepository.SaveChangesAsync();
        return new AuthenticatedUserResponse()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
        };
    }
}
