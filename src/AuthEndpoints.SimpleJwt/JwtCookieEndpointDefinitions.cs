using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthEndpoints.Core;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.Core.Services;
using AuthEndpoints.SimpleJwt.Core;
using AuthEndpoints.SimpleJwt.Core.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.SimpleJwt;

public class JwtCookieEndpointDefinitions<TKey, TUser> : IEndpointDefinition
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>, new()
{
    public virtual void MapEndpoints(WebApplication app)
    {
        app.MapPost("/jwt/create", Create).WithTags("Json Web Token");
        app.MapPost("/jwt/refresh", Refresh).WithTags("Json Web Token");
        app.MapGet("/jwt/verify", Verify).WithTags("Json Web Token");
    }

    /// <summary>
    /// Use this endpoint to login.
    /// </summary>
    /// <remarks>Use this endpoint to obtain jwt</remarks>
    public virtual async Task<IResult> Create([FromBody] LoginRequest request,
                                              IAuthenticator<TUser> authenticator,
                                              JwtHttpOnlyCookieLoginService jwtLoginService,
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

        ClaimsPrincipal userClaimsPrincipal = await claimsFactory.CreateAsync(user);

        await jwtLoginService.LoginAsync(userClaimsPrincipal);

        return Results.NoContent();
    }

    /// <summary>
    /// Use this endpoint to refresh jwt
    /// </summary>
    public virtual async Task<IResult> Refresh(HttpContext context,
                                               IUserClaimsPrincipalFactory<TUser> claimsFactory,
                                               IRefreshTokenValidator tokenValidator,
                                               UserManager<TUser> userManager,
                                               IAccessTokenGenerator tokenGenerator,
                                               IOptions<SimpleJwtOptions> options)
    {
        if (!context.Request.Cookies.TryGetValue("X-Refresh-Token", out string? token))
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
            return Results.BadRequest();
        }

        ClaimsPrincipal principal = await claimsFactory.CreateAsync(user);
        string accessToken = tokenGenerator.GenerateAccessToken(principal);
        context.Response.Cookies.Append("X-Access-Token", accessToken, options.Value.CookieOptions);

        return Results.NoContent();
    }

    [Authorize(AuthenticationSchemes = "jwt")]
    public virtual Task<IResult> Verify()
    {
        return Task.FromResult(Results.NoContent());
    }
}
