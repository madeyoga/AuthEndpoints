using System.Security.Claims;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Completes external login by issuing a JWT access token and refresh cookie, then redirecting.
/// Requires <c>AddJwtEndpoints</c> (or equivalent JWT services) to be registered.
/// </summary>
public sealed class JwtExternalLoginCompleter<TUser> : IExternalLoginCompleter<TUser>
    where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly IUserClaimsPrincipalFactory<TUser> _claimsFactory;
    private readonly IAccessTokenGenerator _accessTokenGenerator;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly RefreshTokenCookieWriter _refreshTokenCookieWriter;
    private readonly ExternalAuthOptions _options;

    public JwtExternalLoginCompleter(
        UserManager<TUser> userManager,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,
        IAccessTokenGenerator accessTokenGenerator,
        IRefreshTokenService refreshTokenService,
        RefreshTokenCookieWriter refreshTokenCookieWriter,
        IOptions<ExternalAuthOptions> options)
    {
        _userManager = userManager;
        _claimsFactory = claimsFactory;
        _accessTokenGenerator = accessTokenGenerator;
        _refreshTokenService = refreshTokenService;
        _refreshTokenCookieWriter = refreshTokenCookieWriter;
        _options = options.Value;
    }

    public async Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        ExternalLoginInfo info,
        string? returnUrl,
        CancellationToken cancellationToken = default)
    {
        var claimsPrincipal = await _claimsFactory.CreateAsync(user);
        var userId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("User principal is missing NameIdentifier.");
        var securityStamp = await _userManager.GetSecurityStampAsync(user);

        var refreshToken = await _refreshTokenService.CreateAsync(userId, securityStamp);
        _refreshTokenCookieWriter.Write(httpContext, refreshToken);

        await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        // Access token is not placed in the URL; SPA should call JWT refresh (with CSRF) after redirect.
        var redirectUrl = ExternalAuthReturnUrl.Resolve(
            returnUrl,
            _options.DefaultReturnUrl,
            _options.AllowedReturnUrlOrigins.ToList());

        return Results.Redirect(redirectUrl);
    }
}
