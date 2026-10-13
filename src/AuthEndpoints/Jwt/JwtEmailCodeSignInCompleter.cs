using System.Security.Claims;
using AuthEndpoints.EmailCode;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Completes email-code sign-in by issuing a Simple JWT access token and HttpOnly refresh cookie.
/// Ignores <c>useCookies</c> and <c>useSessionCookies</c>.
/// Requires <c>AddJwtEndpoints</c> (or equivalent JWT services) to be registered.
/// </summary>
[Obsolete(LegacyCompleterMessages.Obsolete)]
public sealed class JwtEmailCodeSignInCompleter<TUser> : IEmailCodeSignInCompleter<TUser>
    where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly IUserClaimsPrincipalFactory<TUser> _claimsFactory;
    private readonly IAccessTokenGenerator _accessTokenGenerator;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly RefreshTokenCookieWriter _refreshTokenCookieWriter;

    public JwtEmailCodeSignInCompleter(
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
        EmailCodeSignInContext context,
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
