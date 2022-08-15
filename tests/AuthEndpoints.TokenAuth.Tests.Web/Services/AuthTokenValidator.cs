using AuthEndpoints.TokenAuth.Tests.Web.Models;
using AuthEndpoints.TokenAuth.Tests.Web.Repositories;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.TokenAuth.Tests.Web.Services;

public class AuthTokenValidator<TKey, TUser, TContext>
    where TKey : class, IEquatable<TKey>
    where TUser : IdentityUser<TKey>
    where TContext : DbContext
{
    private TokenRepository<TKey, TUser, TContext> tokenRepository { get; set; }

    public AuthTokenValidator(TokenRepository<TKey, TUser, TContext> tokenRepository)
    {
        this.tokenRepository = tokenRepository;
    }

    public Task<Token<TKey, TUser>?> ValidateTokenAsync(string token)
    {
        return tokenRepository.GetByKey(token);
    }
}
