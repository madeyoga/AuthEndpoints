using AuthEndpoints.TokenAuth.Tests.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.TokenAuth.Tests.Web.Data;

public class MyDbContext : IdentityDbContext
{
    public DbSet<Token<string, IdentityUser>>? GetTokens { get; set; }

    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
    {
    }
}
