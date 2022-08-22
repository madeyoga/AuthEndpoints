using AuthEndpoints.Core.Services;
using AuthEndpoints.SimpleJwt.Contracts;
using AuthEndpoints.SimpleJwt.Core;
using AuthEndpoints.SimpleJwt.Core.Models;
using AuthEndpoints.SimpleJwt.Core.Services;

namespace AuthEndpoints.SimpleJwt;

/// <summary>
/// Use this class to log a user in.
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class JwtLoginService<TUser> : ILoginService<TUser>
    where TUser : class
{
    private readonly ITokenGeneratorService<TUser> tokenGenerator;
    private readonly IRefreshTokenRepository refreshTokenRepository;

    public JwtLoginService(ITokenGeneratorService<TUser> tokenGenerator, IRefreshTokenRepository refreshTokenRepository)
    {
        this.tokenGenerator = tokenGenerator;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    /// <summary>
    /// Use this method to get an access Token and a refresh Token for the given TUser
    /// </summary>
    /// <param name="user"></param>
    /// <returns>An instance of <see cref="AuthenticatedUserResponse"/>, containing an access Token and a refresh Token</returns>
    public async Task<object> Login(TUser user)
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
