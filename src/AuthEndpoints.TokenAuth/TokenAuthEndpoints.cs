using System.Security.Claims;
using AuthEndpoints.Core;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.Core.Services;
using AuthEndpoints.TokenAuth.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.TokenAuth;

public class TokenAuthEndpoints<TKey, TUser, TContext> : IEndpointDefinition
    where TKey : class, IEquatable<TKey>
    where TUser : IdentityUser<TKey>
    where TContext : DbContext
{
    public void MapEndpoints(WebApplication app)
    {
        var groupName = "Token Authentication";
        app.MapPost("/token/login", Create).WithTags(groupName);
        app.MapPost("/token/logout", Destroy).WithTags(groupName);
    }

    public virtual async Task<IResult> Create([FromBody] LoginRequest request,
        TokenRepository<TKey, TUser, TContext> tokenRepository,
        IAuthenticator<TUser> authenticator,
        UserManager<TUser> userManager)
    {
        TUser? user = await authenticator.Authenticate(request.Username!, request.Password!);
        if (user is null)
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

        var token = await tokenRepository.GetOrCreate(user.Id);

        return Results.Ok(new TokenAuthResponse
        {
            AuthToken = token.Key
        });
    }

    [Authorize(AuthenticationSchemes = TokenBearerDefaults.AuthenticationScheme)]
    public virtual async Task<IResult> Destroy(HttpContext context,
        TokenRepository<TKey, TUser, TContext> tokenRepository)
    {
        string userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId is null)
        {
            return Results.BadRequest();
        }

        await tokenRepository.DeleteTokenAsync(userId);

        return Results.NoContent();
    }
}
