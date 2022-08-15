using System.Security.Claims;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.Core.Endpoints;
using AuthEndpoints.Core.Services;
using AuthEndpoints.TokenAuth.Tests.Web.Data;
using AuthEndpoints.TokenAuth.Tests.Web.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthEndpoints.TokenAuth.Tests.Web.Endpoints;

public class TokenAuthEndpoints<TKey, TUser> : IEndpointDefinition
    where TKey : class, IEquatable<TKey>
    where TUser : IdentityUser<TKey>
{
    public void MapEndpoints(WebApplication app)
    {
        string groupName = "Token Authentication";
        app.MapPost("/token/login", Create).WithTags(groupName);
        app.MapPost("/token/logout", Destroy).WithTags(groupName);
    }

    public virtual async Task<IResult> Create([FromBody] LoginRequest request,
        TokenRepository<TKey, TUser, MyDbContext> tokenRepository, 
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

        return Results.Ok(new
        {
            AuthToken = token.Key
        });
    }

    [Authorize]
    public virtual async Task<IResult> Destroy(HttpContext context,
        TokenRepository<TKey, TUser, MyDbContext> tokenRepository)
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
