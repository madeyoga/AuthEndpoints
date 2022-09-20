using System.IdentityModel.Tokens.Jwt;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.Core.Endpoints;
using AuthEndpoints.Core.Services;
using AuthEndpoints.SimpleJwt.Contracts;
using AuthEndpoints.SimpleJwt.Core.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.SimpleJwt;

public class JwtCookieEndpointDefinitions<TKey, TUser> : IEndpointDefinition
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>, new()
{
    public virtual void MapEndpoints(WebApplication app)
    {
        app.MapPost("/jwt/create", Create).WithTags("Json Web Token");
        app.MapGet("/jwt/refresh", Refresh).WithTags("Json Web Token");
        app.MapGet("/jwt/verify", Verify).WithTags("Json Web Token");
    }

    /// <summary>
    /// Use this endpoint to login.
    /// </summary>
    /// <remarks>Use this endpoint to obtain jwt</remarks>
    public virtual async Task<IResult> Create([FromBody] LoginRequest request,
        HttpContext context,
        IAuthenticator<TUser> authenticator,
        JwtLoginService<TUser> jwtLoginService,
        UserManager<TUser> userManager)
    {
        TUser? user = await authenticator.Authenticate(request.Username!, request.Password!);

        if (user == null)
        {
            return Results.Unauthorized();
        }

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Results.Ok(new
            {
                AuthSuccess = false,
                TwoStepVerificationRequired = true,
            });
        }

        //await jwtLoginService.LoginAsync(user);

        var response = await jwtLoginService.LoginAsync(user) as AuthenticatedUserResponse;
        context.Response.Cookies.Append("X-Access-Token", response!.AccessToken!, new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Lax });
        context.Response.Cookies.Append("X-Refresh-Token", response.RefreshToken!, new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Lax });

        return Results.NoContent();
    }

    /// <summary>
    /// Use this endpoint to refresh jwt
    /// </summary>
    public virtual async Task<IResult> Refresh(HttpContext context,
        IRefreshTokenValidator tokenValidator,
        UserManager<TUser> userManager,
        IAccessTokenGenerator<TUser> tokenGenerator)
    {
        if (!context.Request.Cookies.TryGetValue("X-Refresh-Token", out var token))
        {
            return Results.BadRequest();
        }

        TokenValidationResult validationResult = await tokenValidator.ValidateRefreshTokenAsync(token!);
        if (!validationResult.IsValid)
        {
            return Results.BadRequest(new ErrorResponse("Invalid refresh token. Token may be expired or revoked by the server."));
        }

        JwtSecurityToken? jwt = validationResult.SecurityToken as JwtSecurityToken;
        string userId = jwt!.Claims.First(claim => claim.Type == "id").Value;
        TUser user = await userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return Results.NotFound(new ErrorResponse("User not found."));
        }

        string accessToken = tokenGenerator.GenerateAccessToken(user);
        context.Response.Cookies.Append("X-Access-Token", accessToken, new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Lax });

        return Results.NoContent();
    }

    [Authorize(AuthenticationSchemes = "jwt")]
    public virtual Task<IResult> Verify()
    {
        return Task.FromResult(Results.NoContent());
    }
}
