using System.Security.Claims;
using AuthEndpoints.Core.Services;
using AuthEndpoints.TokenAuth.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.TokenAuth;

/// <summary>
/// Use this class to log a user in using tokenauth.
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class TokenAuthLoginService<TKey, TUser, TContext> : ILoginService
    where TKey : class, IEquatable<TKey>
    where TUser : IdentityUser<TKey>
    where TContext : DbContext
{
    TokenRepository<TKey, TUser, TContext> tokenRepository;
    private readonly UserManager<TUser> userManager;

    public TokenAuthLoginService(TokenRepository<TKey, TUser, TContext> tokenRepository, UserManager<TUser> userManager)
    {
        this.tokenRepository = tokenRepository;
        this.userManager = userManager;
    }

    /// <summary>
    /// Use this method to log a user in
    /// </summary>
    /// <param name="user"></param>
    /// <returns><see cref="TokenAuthResponse"/></returns>
    public async Task<object> LoginAsync(ClaimsPrincipal user)
    {
        TUser identityUser = await userManager.FindByIdAsync(user.FindFirstValue(ClaimTypes.NameIdentifier));
        var token = await tokenRepository.GetOrCreate(identityUser.Id);

        return new TokenAuthResponse
        {
            AuthToken = token.Key,
        };
    }
}
