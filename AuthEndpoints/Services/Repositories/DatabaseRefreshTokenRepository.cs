using AuthEndpoints.Data;
using AuthEndpoints.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Services.Repositories;

public class DatabaseRefreshTokenRepository<TUserKey, TUser, TRefreshToken> : IRefreshTokenRepository<TUserKey, TRefreshToken>
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
    where TRefreshToken : GenericRefreshToken<TUser, TUserKey>
{
    private readonly IAuthDbContext<TUser, TRefreshToken> context;

    public DatabaseRefreshTokenRepository(IAuthDbContext<TUser, TRefreshToken> context)
    {
        this.context = context;
    }

    public async Task Create(TRefreshToken refreshToken)
    {
        context.RefreshTokens?.Add(refreshToken);
        await context.SaveChangesAsync();
    }

    public async Task Delete(Guid refreshTokenId)
    {
        TRefreshToken? refreshToken = await context.RefreshTokens!.FindAsync(refreshTokenId);
        if (refreshToken != null)
        {
            context.RefreshTokens.Remove(refreshToken);
            await context.SaveChangesAsync();
        }
    }

    public async Task DeleteAll(TUserKey userId)
    {
        IEnumerable<TRefreshToken> refreshTokens = await context.RefreshTokens!.Where(t => t.UserId!.Equals(userId)).ToListAsync();

        context.RefreshTokens!.RemoveRange(refreshTokens);
        await context.SaveChangesAsync();
    }

    public async Task<TRefreshToken?> GetByToken(string token)
    {
        return await context.RefreshTokens!.FirstOrDefaultAsync(refreshToken => refreshToken.Token == token);
    }
}

