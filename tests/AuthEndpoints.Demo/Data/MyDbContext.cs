using AuthEndpoints.Demo.Models;
using AuthEndpoints.SimpleJwt.Core.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Demo.Data;

public class MyDbContext : IdentityDbContext<MyCustomIdentityUser>
{
    public DbSet<RefreshToken>? RefreshTokens { get; set; }

    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
    }
}
