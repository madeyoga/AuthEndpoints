using System.Security.Claims;
using AuthEndpoints.Identity;
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

        var authenticationResult = await authenticator.AuthenticateAsync(request.Email, request.Password);
        var user = authenticationResult.User;

        if (user == null)
        {
            return Results.Problem(
                detail: "Invalid credentials.",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            if (!string.IsNullOrEmpty(request.TwoFactorCode))
            {
                bool validToken = await userManager.VerifyTwoFactorTokenAsync(
                    user,
                    userManager.Options.Tokens.AuthenticatorTokenProvider,
                    request.TwoFactorCode);
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
            else
            {
                return Results.Problem(
                    detail: "Two-factor authentication is required.",
                    statusCode: StatusCodes.Status401Unauthorized,
                    extensions: new Dictionary<string, object?>
                    {
                        ["requiresTwoFactor"] = true
                    });
            }
        }

        var claimsPrincipal = await claimsFactory.CreateAsync(user);
        var userId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var securityStamp = await userManager.GetSecurityStampAsync(user);

        var response = new SimpleJwtTokenResponse
        {
            AccessToken = accessTokenGenerator.GenerateAccessToken(claimsPrincipal),
            TokenType = "Bearer",
        };

        var refreshToken = await refreshTokenService.CreateAsync(userId, securityStamp);
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
        if (!context.Request.Cookies.TryGetValue(RefreshTokenCookieWriter.CookieName, out var refreshTokenValue)
            || string.IsNullOrEmpty(refreshTokenValue))
        {
            return Results.BadRequest(new SimpleJwtErrorResponse("Missing refresh token cookie."));
        }

        var refreshToken = await refreshTokenService.GetRefreshTokenAsync(refreshTokenValue);

        if (refreshToken == null)
        {
            return Results.BadRequest(new SimpleJwtErrorResponse("Invalid refresh token. Token may be expired or revoked by the server."));
        }

        if (refreshToken.RevokedAt != null)
        {
            if (refreshToken.ReplacedByTokenId != null)
            {
                await refreshTokenService.RevokeFamilyAsync(refreshToken.FamilyId);
            }

            refreshTokenCookieWriter.Delete(context);
            return Results.BadRequest(new SimpleJwtErrorResponse("Invalid refresh token. Token may be expired or revoked by the server."));
        }

        if (!refreshTokenService.IsValid(refreshToken))
        {
            return Results.BadRequest(new SimpleJwtErrorResponse("Invalid refresh token. Token may be expired or revoked by the server."));
        }

        var user = await userManager.FindByIdAsync(refreshToken.UserId);
        if (user == null)
        {
            await refreshTokenService.RevokeAsync(refreshToken);
            refreshTokenCookieWriter.Delete(context);
            return Results.BadRequest(new SimpleJwtErrorResponse("Associated user no longer exists."));
        }

        var currentStamp = await userManager.GetSecurityStampAsync(user);
        if (!string.Equals(refreshToken.SecurityStamp, currentStamp, StringComparison.Ordinal))
        {
            await refreshTokenService.RevokeFamilyAsync(refreshToken.FamilyId);
            refreshTokenCookieWriter.Delete(context);
            return Results.BadRequest(new SimpleJwtErrorResponse("Invalid refresh token. Token may be expired or revoked by the server."));
        }

        var newRefreshToken = await refreshTokenService.RotateAsync(refreshToken, currentStamp);
        refreshTokenCookieWriter.Write(context, newRefreshToken);

        var claimsPrincipal = await claimsFactory.CreateAsync(user);

        return Results.Ok(new
        {
            AccessToken = tokenGenerator.GenerateAccessToken(claimsPrincipal),
        });
    }

    /// <summary>
    /// Clears the refresh cookie and revokes the current token family.
    /// </summary>
    public static async Task<IResult> Logout(
        HttpContext context,
        IRefreshTokenService refreshTokenService,
        RefreshTokenCookieWriter refreshTokenCookieWriter)
    {
        if (context.Request.Cookies.TryGetValue(RefreshTokenCookieWriter.CookieName, out var refreshTokenValue)
            && !string.IsNullOrEmpty(refreshTokenValue))
        {
            var refreshToken = await refreshTokenService.GetRefreshTokenAsync(refreshTokenValue);
            if (refreshToken != null)
            {
                await refreshTokenService.RevokeFamilyAsync(refreshToken.FamilyId);
            }
        }

        refreshTokenCookieWriter.Delete(context);
        return Results.Ok();
    }

    /// <summary>
    /// Use this endpoint to verify access jwt
    /// </summary>
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public static IResult Verify()
    {
        return Results.NoContent();
    }

    /// <summary>
    /// Returns an antiforgery token for cookie-backed JWT refresh/logout.
    /// </summary>
    public static IResult GetAntiforgeryToken(
        Microsoft.AspNetCore.Antiforgery.IAntiforgery forgeryService,
        HttpContext context)
        => IdentityApiEndpoints<TUser>.GetAntiforgeryToken(forgeryService, context);
}
