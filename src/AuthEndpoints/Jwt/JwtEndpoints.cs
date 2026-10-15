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

        var session = JwtRefreshDelivery.Session(context);
        var refreshToken = await refreshTokenService.CreateAsync(userId, securityStamp);
        JwtRefreshDelivery.WriteCookie(context, refreshTokenCookieWriter, refreshToken, session);
        JwtRefreshDelivery.ApplyBody(response, refreshToken, session);

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
        var session = JwtRefreshDelivery.Session(context);
        var presented = await JwtRefreshDelivery.ReadPresentedTokenAsync(context, session);
        if (presented.UnsupportedMediaType)
        {
            return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
        }

        var refreshTokenValue = presented.Value;
        if (string.IsNullOrEmpty(refreshTokenValue))
        {
            return Results.BadRequest(new SimpleJwtErrorResponse(
                JwtRefreshDelivery.IsBody(session)
                    ? "Missing refresh token."
                    : "Missing refresh token cookie."));
        }

        var refreshToken = await refreshTokenService.GetRefreshTokenAsync(refreshTokenValue);

        if (refreshToken == null)
        {
            return InvalidRefresh(context, refreshTokenCookieWriter, session);
        }

        if (refreshToken.RevokedAt != null)
        {
            if (refreshToken.ReplacedByTokenId != null)
            {
                await refreshTokenService.RevokeFamilyAsync(refreshToken.FamilyId);
            }

            return InvalidRefresh(context, refreshTokenCookieWriter, session);
        }

        if (!refreshTokenService.IsValid(refreshToken))
        {
            return InvalidRefresh(context, refreshTokenCookieWriter, session);
        }

        var user = await userManager.FindByIdAsync(refreshToken.UserId);
        if (user == null)
        {
            await refreshTokenService.RevokeAsync(refreshToken);
            return InvalidRefresh(
                context,
                refreshTokenCookieWriter,
                session,
                "Associated user no longer exists.");
        }

        var currentStamp = await userManager.GetSecurityStampAsync(user);
        if (!string.Equals(refreshToken.SecurityStamp, currentStamp, StringComparison.Ordinal))
        {
            await refreshTokenService.RevokeFamilyAsync(refreshToken.FamilyId);
            return InvalidRefresh(context, refreshTokenCookieWriter, session);
        }

        var newRefreshToken = await refreshTokenService.RotateAsync(refreshToken, currentStamp);
        if (newRefreshToken is null)
        {
            // Lost the rotation race (the family is revoked) or the token expired between checks.
            return InvalidRefresh(context, refreshTokenCookieWriter, session);
        }

        JwtRefreshDelivery.WriteCookie(context, refreshTokenCookieWriter, newRefreshToken, session);

        var claimsPrincipal = await claimsFactory.CreateAsync(user);
        var accessToken = tokenGenerator.GenerateAccessToken(claimsPrincipal);
        if (JwtRefreshDelivery.IsBody(session))
        {
            return Results.Ok(new SimpleJwtTokenResponse
            {
                AccessToken = accessToken,
                TokenType = "Bearer",
                RefreshToken = newRefreshToken.Token,
            });
        }

        return Results.Ok(new
        {
            AccessToken = accessToken,
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
        var session = JwtRefreshDelivery.Session(context);
        var presented = await JwtRefreshDelivery.ReadPresentedTokenAsync(context, session);
        if (presented.UnsupportedMediaType)
        {
            return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
        }

        var refreshTokenValue = presented.Value;
        if (!string.IsNullOrEmpty(refreshTokenValue))
        {
            var refreshToken = await refreshTokenService.GetRefreshTokenAsync(refreshTokenValue);
            if (refreshToken != null)
            {
                await refreshTokenService.RevokeFamilyAsync(refreshToken.FamilyId);
            }
        }

        JwtRefreshDelivery.DeleteCookie(context, refreshTokenCookieWriter, session);
        return Results.Ok();
    }

    private static IResult InvalidRefresh(
        HttpContext context,
        RefreshTokenCookieWriter refreshTokenCookieWriter,
        JwtSessionOptions session,
        string message = "Invalid refresh token. Token may be expired or revoked by the server.")
    {
        JwtRefreshDelivery.DeleteCookie(context, refreshTokenCookieWriter, session);
        return Results.BadRequest(new SimpleJwtErrorResponse(message));
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
