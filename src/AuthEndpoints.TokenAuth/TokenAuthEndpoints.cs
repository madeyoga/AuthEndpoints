namespace AuthEndpoints.TokenAuth;

using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

public class TokenAuthEndpoints<TKey, TUser, TContext>
    where TUser : class
{
    public void MapEndpoints(WebApplication app)
    {
        var groupName = "Token Authentication";
        app.MapPost("/token/login", Create).WithTags(groupName);
    }

    public virtual async Task<Results<Ok<LoginResponse>, EmptyHttpResult, ProblemHttpResult>> Create([FromBody] LoginRequest request, [FromServices] SignInManager<TUser> signInManager)
    {
        //signInManager.PrimaryAuthenticationScheme = IdentityConstants.BearerScheme;

        var result = await signInManager.PasswordSignInAsync(request.Email, request.Password, false, lockoutOnFailure: true);

        if (!result.Succeeded)
        {
            return TypedResults.Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
        }

        return TypedResults.Empty;
    }
}

public sealed class LoginRequest
{
    public required string Email { get; init; }

    public required string Password { get; init; }
}

public sealed class LoginResponse
{
    public string TokenType { get; } = "Bearer";

    public required string AccessToken { get; init; }

    public required long ExpiresIn { get; init; }

    public required string RefreshToken { get; init; }
}
