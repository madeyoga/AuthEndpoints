using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.TokenAuth.Core;

public class TokenRepository<TKey, TUser, TContext>
    where TKey : class, IEquatable<TKey>
    where TUser : IdentityUser<TKey>
    where TContext : DbContext
{
    private readonly TContext context;
    private readonly AuthTokenGenerator tokenGenerator;

    private readonly DbSet<Token<TKey, TUser>> tokens;

    public TokenRepository(TContext context, AuthTokenGenerator tokenGenerator)
    {
        this.context = context;
        this.tokenGenerator = tokenGenerator;
        tokens = context.Set<Token<TKey, TUser>>();
    }

    public async Task<Token<TKey, TUser>?> GetByKey(string key)
    {
        return await tokens.Where(token => token.Key == key).Include(token => token.GetUser).FirstOrDefaultAsync();
    }

    public async Task<List<Token<TKey, TUser>>> FindByUserAsync(TUser user)
    {
        var token = await tokens.Where(token => token.GetUserId == user.Id).ToListAsync();
        return token;
    }

    public async Task<List<Token<TKey, TUser>>> FindByUserIdAsync(TKey userId)
    {
        var token = await tokens.Where(token => token.GetUserId == userId).ToListAsync();
        return token;
    }

    public async Task DeleteTokenAsync(string userId)
    {
        var userTokens = tokens.Where(token => token.GetUserId!.ToString() == userId);
        context.RemoveRange(userTokens);
        await context.SaveChangesAsync();
    }

    public async Task<Token<TKey, TUser>> CreateAsync(TKey userId, string key)
    {
        var token = new Token<TKey, TUser>()
        {
            Key = key,
            GetUserId = userId,
        };
        await context.AddAsync(token);
        await context.SaveChangesAsync();
        return token;
    }

    public async Task<Token<TKey, TUser>> GetOrCreate(TKey userId)
    {
        var userTokens = await FindByUserIdAsync(userId);
        if (userTokens.Count > 0)
        {
            return userTokens.First();
        }
        var token = await CreateAsync(userId, await tokenGenerator.GenerateToken());
        return token;
    }
}
