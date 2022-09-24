using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthEndpoints.Core;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.Core.Services;
using AuthEndpoints.SimpleJwt.Core.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.SimpleJwt;

/// <summary>
/// Minimal Api definitions for JWT endpoints.
/// </summary>
/// <typeparam name="TKey"></typeparam>
/// <typeparam name="TUser"></typeparam>
public class JwtEndpointDefinition<TKey, TUser> : IEndpointDefinition
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>, new()
{
    public virtual void MapEndpoints(WebApplication app)
    {
        string baseUrl = "/jwt";
        app.MapPost($"{baseUrl}/create", Create).WithTags("Json Web Token");
        app.MapPost($"{baseUrl}/refresh", Refresh).WithTags("Json Web Token");
        app.MapGet($"{baseUrl}/verify", Verify).WithTags("Json Web Token");
    }

    /// <summary>
    /// Use this endpoint to obtain jwt
    /// </summary>
    /// <remarks>Use this endpoint to obtain jwt</remarks>
    public virtual async Task<IResult> Create([FromBody] LoginRequest request,
                                              IAuthenticator<TUser> authenticator,
                                              JwtLoginService jwtLoginService,
                                              UserManager<TUser> userManager,
                                              IUserClaimsPrincipalFactory<TUser> claimsFactory)
    {
        TUser? user = await authenticator.Authenticate(request.Username!, request.Password!);

        if (user == null)
        {
            return Results.BadRequest();
        }

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Results.Ok(new
            {
                AuthSuccess = false,
                TwoStepVerificationRequired = true,
            });
        }
        ClaimsPrincipal principal = await claimsFactory.CreateAsync(user);

        var response = await jwtLoginService.LoginAsync(principal);

        return Results.Ok(response);
    }

    /// <summary>
    /// Use this endpoint to refresh jwt
    /// </summary>
    public virtual async Task<IResult> Refresh([FromBody] RefreshRequest request,
                                               HttpContext context,
                                               IRefreshTokenValidator tokenValidator,
                                               UserManager<TUser> userManager,
                                               IAccessTokenGenerator tokenGenerator,
                                               IUserClaimsPrincipalFactory<TUser> claimsFactory)
    {
        TokenValidationResult validationResult = await tokenValidator.ValidateRefreshTokenAsync(request.RefreshToken!);

        if (!validationResult.IsValid)
        {
            // Token may be expired, invalid, etc.
            return Results.BadRequest(new ErrorResponse("Invalid refresh token. Token may be expired or revoked by the server."));
        }

        JwtSecurityToken? jwt = validationResult.SecurityToken as JwtSecurityToken;
        string userId = jwt!.Claims.First(claim => claim.Type == "id").Value;
        TUser user = await userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return Results.NotFound(new ErrorResponse("User not found."));
        }

        return Results.Ok(new
        {
            AccessToken = tokenGenerator.GenerateAccessToken(await claimsFactory.CreateAsync(user))
        });
    }

    /// <summary>
    /// Use this endpoint to verify access jwt
    /// </summary>
    [Authorize(AuthenticationSchemes = "jwt")]
    public virtual Task<IResult> Verify()
    {
        return Task.FromResult(Results.NoContent());
    }
}
