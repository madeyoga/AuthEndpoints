using AuthEndpoints.Core.Services;
using AuthEndpoints.TokenAuth.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.TokenAuth;

/// <summary>
/// Use this class to log a user in using tokenauth.
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class TokenAuthLoginService<TKey, TUser, TContext> : ILoginService<TUser>
    where TKey : class, IEquatable<TKey>
    where TUser : IdentityUser<TKey>
    where TContext : DbContext
{
    TokenRepository<TKey, TUser, TContext> tokenRepository;

    public TokenAuthLoginService(TokenRepository<TKey, TUser, TContext> tokenRepository)
    {
        this.tokenRepository = tokenRepository;
    }

    /// <summary>
    /// Use this method to log a user in
    /// </summary>
    /// <param name="user"></param>
    /// <returns><see cref="TokenAuthResponse"/></returns>
    public async Task<object> Login(TUser user)
    {
        var token = await tokenRepository.GetOrCreate(user.Id);

        return new TokenAuthResponse
        {
            AuthToken = token.Key,
        };
    }
}
