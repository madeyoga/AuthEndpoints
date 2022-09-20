using AuthEndpoints.SimpleJwt.Contracts;
using AuthEndpoints.SimpleJwt.Core.Models;
using AuthEndpoints.SimpleJwt.Core.Services;
using AuthEndpoints.SimpleJwt.Core;
using Microsoft.AspNetCore.Http;
using AuthEndpoints.Core.Services;

namespace AuthEndpoints.SimpleJwt;

public class JwtHttpOnlyCookieLoginService<TUser> : ILoginService<TUser>
    where TUser : class
{
    private readonly ITokenGeneratorService<TUser> tokenGenerator;
    private readonly IRefreshTokenRepository refreshTokenRepository;
    private readonly IHttpContextAccessor httpContextAccessor;

    public JwtHttpOnlyCookieLoginService(ITokenGeneratorService<TUser> tokenGenerator,
                                         IRefreshTokenRepository refreshTokenRepository,
                                         IHttpContextAccessor httpContextAccessor)
    {
        this.tokenGenerator = tokenGenerator;
        this.refreshTokenRepository = refreshTokenRepository;
        this.httpContextAccessor = httpContextAccessor;
    }

    /// <summary>
    /// Use this method to get an access Token and a refresh Token for the given TUser
    /// </summary>
    /// <param name="user"></param>
    /// <returns>An instance of <see cref="AuthenticatedUserResponse"/>, containing an access Token and a refresh Token</returns>
    public async Task<object> LoginAsync(TUser user)
    {
        var accessToken = tokenGenerator.GenerateAccessToken(user);
        var refreshToken = tokenGenerator.GenerateRefreshToken(user);
        await refreshTokenRepository.AddAsync(new RefreshToken
        {
            Token = refreshToken,
        });
        await refreshTokenRepository.SaveChangesAsync();

        var context = httpContextAccessor.HttpContext!;
        context.Response.Cookies.Append("X-Access-Token", accessToken, new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Lax });
        context.Response.Cookies.Append("X-Refresh-Token", refreshToken, new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Lax });

        return new AuthenticatedUserResponse()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
        };
    }
}
