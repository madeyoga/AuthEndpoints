using AuthEndpoints.Data;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Demo.Data;

public class MyDbContext
    : DbContext, IAuthDbContext<MyCustomIdentityUser, RefreshToken>
{
    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
    }

    public DbSet<MyCustomIdentityUser>? Users { get; set; }
    public DbSet<RefreshToken>? RefreshTokens { get; set; }
    public DbSet<Token<MyCustomIdentityUser>>? Tokens { get; set; }
}
