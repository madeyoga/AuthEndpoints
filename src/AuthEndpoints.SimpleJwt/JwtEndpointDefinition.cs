using System.Text.Json;
using AuthEndpoints.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.SimpleJwt;

/// <summary>
/// Minimal Api definitions for JWT endpoints.
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class JwtEndpointDefinition<TUser> : IEndpointDefinition
    where TUser : class, new()
{
    public virtual void MapEndpoints(WebApplication app)
    {
        string baseUrl = "/jwt";
        string tags = "Authentication and Authorization";
        app.MapPost($"{baseUrl}/create", Create).WithTags(tags);
        app.MapPost($"{baseUrl}/refresh", Refresh).WithTags(tags);
        app.MapGet($"{baseUrl}/verify", Verify).WithTags(tags);
    }

    /// <summary>
    /// Use this endpoint to obtain jwt
    /// </summary>
    /// <remarks>Use this endpoint to obtain jwt</remarks>
    public static async Task<IResult> Create([FromBody] SimpleJwtLoginRequest request,
        IAuthenticator<TUser> authenticator,
        UserManager<TUser> userManager,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,
        IAccessTokenGenerator accessTokenGenerator,
        IRefreshTokenService refreshTokenGenerator)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "The request is missing a required body username or password"
            });
        }

        AuthenticationResult<TUser>? authenticationResult = await authenticator.AuthenticateAsync(request.Username, request.Password);

        if (!authenticationResult.Succeeded)
        {
            var error = authenticationResult.Errors.First();
            return Results.BadRequest(new
            {
                error = error.Code,
                error_description = error.Description,
            });
        }

        var user = authenticationResult.User!;
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
            else
            {
                return Results.Problem("Requires two factor", statusCode: StatusCodes.Status401Unauthorized);
            }
        }

        var claimsPrincipal = await claimsFactory.CreateAsync(user);

        var response = new SimpleJwtTokenResponse()
        {
            AccessToken = accessTokenGenerator.GenerateAccessToken(claimsPrincipal),
            RefreshToken = refreshTokenGenerator.GenerateRefreshToken(claimsPrincipal),
            TokenType = "Bearer",
        };

        return Results.Ok(response);
    }

    /// <summary>
    /// Use this endpoint to refresh jwt
    /// </summary>
    public static async Task<IResult> Refresh([FromBody] SimpleJwtRefreshTokenRequest request,
        IRefreshTokenValidator tokenValidator,
        UserManager<TUser> userManager,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,
        IAccessTokenGenerator tokenGenerator,
        IDataProtectionProvider dataProtectionProvider)
    {
        TokenValidationResult validationResult = await tokenValidator.ValidateRefreshTokenAsync(request.RefreshToken!);

        if (!validationResult.IsValid)
        {
            // Token may be expired, invalid, etc.
            return Results.BadRequest(new SimpleJwtErrorResponse("Invalid refresh token. Token may be expired or revoked by the server."));
        }
        var _dataProtector = dataProtectionProvider.CreateProtector("authendpoints_simplejwt_refreshtoken");
        var codeString = _dataProtector.Unprotect(request.RefreshToken!);
        var data = JsonSerializer.Deserialize<SimpleJwtRefreshTokenData>(codeString);
        var user = await userManager.FindByIdAsync(data!.NameIdentifier);
        var claimsPrincipal = await claimsFactory.CreateAsync(user!);

        return Results.Ok(new
        {
            AccessToken = tokenGenerator.GenerateAccessToken(claimsPrincipal),
        });
    }

    /// <summary>
    /// Use this endpoint to verify access jwt
    /// </summary>
    [Authorize(AuthenticationSchemes = "jwt")]
    public static Task<IResult> Verify()
    {
        return Task.FromResult(Results.NoContent());
    }
}
