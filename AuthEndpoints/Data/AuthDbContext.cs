using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Data;

public abstract class AuthDbContext<TUser, TRefreshToken> : DbContext, IRefreshTokenDbContext<TUser, TRefreshToken>
    where TUser : class
    where TRefreshToken : class
{
    public DbSet<TRefreshToken>? RefreshTokens { get; set; }

    public AuthDbContext(DbContextOptions options) : base(options)
    {
    }
}
