using System.IdentityModel.Tokens.Jwt;
using AuthEndpoints.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.MinimalApi;

public class JwtEndpointDefinition<TKey, TUser> : IEndpointDefinition, IJwtEndpointDefinition<TKey, TUser> 
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>, new()
{
    public void MapEndpoints(WebApplication app)
    {
        string baseUrl = "/jwt";
        app.MapPost($"{baseUrl}/create", Create);
        app.MapPost($"{baseUrl}/refresh", Refresh);
        app.MapGet($"{baseUrl}/verify", Verify);
    }

    /// <summary>
    /// Use this endpoint to obtain jwt
    /// </summary>
    /// <remarks>Use this endpoint to obtain jwt</remarks>
    public virtual async Task<IResult> Create([FromBody] LoginRequest request,
        IAuthenticator<TUser> authenticator,
        UserManager<TUser> userManager)
    {
        //if (!ModelState.IsValid)
        //{
        //    return BadRequestModelState();
        //}

        TUser? user = await authenticator.Authenticate(request.Username, request.Password);

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

        AuthenticatedUserResponse response = await authenticator.Login(user);

        return Results.Ok(response);
    }

    /// <summary>
    /// Use this endpoint to refresh jwt
    /// </summary>
    public virtual async Task<IResult> Refresh([FromBody] RefreshRequest request,
        IJwtValidator jwtValidator,
        IOptions<AuthEndpointsOptions> options,
        UserManager<TUser> userManager,
        IAuthenticator<TUser> authenticator)
    {
        //if (!ModelState.IsValid)
        //{
        //    return BadRequestModelState();
        //}

        bool isValidRefreshToken = jwtValidator.Validate(request.RefreshToken,
            options.Value.RefreshValidationParameters!);

        if (!isValidRefreshToken)
        {
            // Token may be expired, invalid, etc. but this good enough for now.
            return Results.BadRequest(new ErrorResponse("Invalid refresh token. Token may be expired or invalid."));
        }

        JwtSecurityToken jwt = jwtValidator.ReadJwtToken(request.RefreshToken);
        string userId = jwt.Claims.First(claim => claim.Type == "id").Value;
        TUser user = await userManager.FindByIdAsync(userId);

        if (user == null)
        {
            return Results.NotFound(new ErrorResponse("User not found."));
        }

        AuthenticatedUserResponse response = await authenticator.Login(user);

        return Results.Ok(response);
    }

    /// <summary>
    /// Use this endpoint to verify access jwt
    /// </summary>
    [Authorize(AuthenticationSchemes = "jwt")]
    public virtual IResult Verify()
    {
        return Results.Ok();
    }
}
