using AuthEndpoints.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Data;

public abstract class AuthDbContext<TUser, TRefreshToken> : DbContext, IAuthDbContext<TUser, TRefreshToken>
    where TUser : class
    where TRefreshToken : class
{
    public DbSet<Token<TUser>>? Tokens { get; set; }
    public DbSet<TRefreshToken>? RefreshTokens { get; set; }

    public AuthDbContext(DbContextOptions options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Token<TUser>>()
            .Property(token => token.Created)
            .HasDefaultValueSql("getdate()");
    }
}
