using AuthEndpoints.Demo.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Demo.Data;

public class MyDbContext : DbContext
{
    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
    }

    public DbSet<MyCustomIdentityUser>? Users { get; set; }
}
