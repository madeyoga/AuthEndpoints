using AuthEndpoints.Core.Models;
using AuthEndpoints.Demo.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Demo.Data;

public class MyDbContext : DbContext
{
    public DbSet<RefreshToken>? RefreshTokens { get; set; }
    public DbSet<MyCustomIdentityUser>? Users { get; set; }

    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
    }
}
