using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Jwt endpoint definitions.
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class JwtEndpoints<TUser>
    where TUser : class, new()
{
    /// <summary>
    /// Use this endpoint to obtain jwt
    /// </summary>
    /// <remarks>Use this endpoint to obtain jwt</remarks>
    public static async Task<IResult> Create(
        [FromBody] SimpleJwtLoginRequest request,
        IAuthenticator<TUser> authenticator,
        UserManager<TUser> userManager,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,
        IAccessTokenGenerator accessTokenGenerator,
        IRefreshTokenService refreshTokenService,
        RefreshTokenCookieWriter refreshTokenCookieWriter,
        HttpContext context)
    {
        if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "The request is missing a required body username or password"
            });
        }

        AuthenticationResult<TUser>? authenticationResult = await authenticator.AuthenticateAsync(request.Email, request.Password);

        var user = authenticationResult.User;

        if (user == null)
        {
            return Results.Problem("Invalid credentials");
        }

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            if (!string.IsNullOrEmpty(request.TwoFactorCode))
            {
                bool validToken = await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, request.TwoFactorCode);
                if (!validToken)
                {
                    return Results.Problem("Invalid two factor code.", statusCode: StatusCodes.Status401Unauthorized);
                }
            }
            else if (!string.IsNullOrEmpty(request.TwoFactorRecoveryCode))
            {
                var result = await userManager.RedeemTwoFactorRecoveryCodeAsync(user, request.TwoFactorRecoveryCode);
                if (!result.Succeeded)
                {
                    return Results.Problem(result.Errors.First().Description, statusCode: StatusCodes.Status401Unauthorized);
                }
            }
        }

        var claimsPrincipal = await claimsFactory.CreateAsync(user);

        var response = new SimpleJwtTokenResponse()
        {
            AccessToken = accessTokenGenerator.GenerateAccessToken(claimsPrincipal),
            TokenType = "Bearer",
        };

        var refreshToken = await refreshTokenService.CreateAsync(claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)!);

        refreshTokenCookieWriter.Write(context, refreshToken);

        return Results.Ok(response);
    }

    /// <summary>
    /// Use this endpoint to refresh jwt
    /// </summary>
    public static async Task<IResult> Refresh(
        HttpContext context,
        IRefreshTokenService refreshTokenService,
        IAccessTokenGenerator tokenGenerator,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,
        UserManager<TUser> userManager,
        RefreshTokenCookieWriter refreshTokenCookieWriter)
    {
        if (!context.Request.Cookies.TryGetValue("AuthEndpoints.Jwt.RefreshToken", out var refreshTokenValue))
        {
            return Results.BadRequest(new SimpleJwtErrorResponse("Missing refresh token cookie."));
        }

        var refreshToken = await refreshTokenService.GetRefreshTokenAsync(refreshTokenValue);

        if (refreshToken == null)
        {
            return Results.BadRequest(new SimpleJwtErrorResponse("Invalid refresh token. Token may be expired or revoked by the server."));
        }
        if (!refreshTokenService.IsValid(refreshToken))
        {
            return Results.BadRequest(new SimpleJwtErrorResponse("Invalid refresh token. Token may be expired or revoked by the server."));
        }

        var user = await userManager.FindByIdAsync(refreshToken.UserId);
        if (user == null)
        {
            return Results.BadRequest(new SimpleJwtErrorResponse("Associated user no longer exists."));
        }

        var newRefreshToken = await refreshTokenService.RotateAsync(refreshToken);

        refreshTokenCookieWriter.Write(context, newRefreshToken);

        var claimsPrincipal = await claimsFactory.CreateAsync(user);

        return Results.Ok(new
        {
            AccessToken = tokenGenerator.GenerateAccessToken(claimsPrincipal),
        });
    }

    /// <summary>
    /// Use this endpoint to verify access jwt
    /// </summary>
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public static IResult Verify()
    {
        return Results.NoContent();
    }
}
