using System.Security.Claims;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Completes passkey register/login by issuing a Simple JWT access token and HttpOnly refresh cookie
/// (same response shape as JWT <c>/create</c>). Ignores <c>useCookies</c> / <c>useSessionCookies</c>.
/// Requires <c>AddJwtEndpoints</c> (or equivalent JWT services) to be registered.
/// </summary>
public sealed class JwtPasskeySignInCompleter<TUser> : IPasskeySignInCompleter<TUser>
    where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly IUserClaimsPrincipalFactory<TUser> _claimsFactory;
    private readonly IAccessTokenGenerator _accessTokenGenerator;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly RefreshTokenCookieWriter _refreshTokenCookieWriter;

    public JwtPasskeySignInCompleter(
        UserManager<TUser> userManager,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,
        IAccessTokenGenerator accessTokenGenerator,
        IRefreshTokenService refreshTokenService,
        RefreshTokenCookieWriter refreshTokenCookieWriter)
    {
        _userManager = userManager;
        _claimsFactory = claimsFactory;
        _accessTokenGenerator = accessTokenGenerator;
        _refreshTokenService = refreshTokenService;
        _refreshTokenCookieWriter = refreshTokenCookieWriter;
    }

    public async Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        PasskeySignInCompletionContext context,
        CancellationToken cancellationToken = default)
    {
        var claimsPrincipal = await _claimsFactory.CreateAsync(user);
        var userId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("User principal is missing NameIdentifier.");
        var securityStamp = await _userManager.GetSecurityStampAsync(user);

        var response = new SimpleJwtTokenResponse
        {
            AccessToken = _accessTokenGenerator.GenerateAccessToken(claimsPrincipal),
            TokenType = "Bearer",
        };

        var refreshToken = await _refreshTokenService.CreateAsync(userId, securityStamp);
        _refreshTokenCookieWriter.Write(httpContext, refreshToken);

        return Results.Ok(response);
    }
}
