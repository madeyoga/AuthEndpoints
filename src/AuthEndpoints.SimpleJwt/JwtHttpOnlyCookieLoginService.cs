using System.Security.Claims;
using AuthEndpoints.Core.Services;
using AuthEndpoints.SimpleJwt.Contracts;
using AuthEndpoints.SimpleJwt.Core;
using AuthEndpoints.SimpleJwt.Core.Models;
using AuthEndpoints.SimpleJwt.Core.Services;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.SimpleJwt;

public class JwtHttpOnlyCookieLoginService : ILoginService
{
    private readonly ITokenGeneratorService tokenGenerator;
    private readonly IRefreshTokenRepository refreshTokenRepository;
    private readonly IOptions<SimpleJwtOptions> options;
    private readonly IHttpContextAccessor httpContextAccessor;

    public JwtHttpOnlyCookieLoginService(ITokenGeneratorService tokenGenerator,
                                         IRefreshTokenRepository refreshTokenRepository,
                                         IOptions<SimpleJwtOptions> options, 
                                         IHttpContextAccessor httpContextAccessor)
    {
        this.tokenGenerator = tokenGenerator;
        this.refreshTokenRepository = refreshTokenRepository;
        this.options = options;
        this.httpContextAccessor = httpContextAccessor;
    }

    /// <summary>
    /// Use this method to get an access Token and a refresh Token for the given TUser
    /// </summary>
    /// <param name="user"></param>
    /// <returns>An instance of <see cref="AuthenticatedUserResponse"/>, containing an access Token and a refresh Token</returns>
    public async Task<object> LoginAsync(ClaimsPrincipal user)
    {
        var accessToken = tokenGenerator.GenerateAccessToken(user);
        var refreshToken = tokenGenerator.GenerateRefreshToken(user);
        await refreshTokenRepository.AddAsync(new RefreshToken
        {
            Token = refreshToken,
        });
        await refreshTokenRepository.SaveChangesAsync();
        var context = httpContextAccessor.HttpContext!;
        context.Response.Cookies.Append("X-Access-Token", accessToken, options.Value.CookieOptions);
        context.Response.Cookies.Append("X-Refresh-Token", refreshToken, options.Value.CookieOptions);

        return new AuthenticatedUserResponse()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
        };
    }
}
