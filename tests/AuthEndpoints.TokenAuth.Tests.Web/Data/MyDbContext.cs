using AuthEndpoints.SimpleJwt.Core.Models;
using AuthEndpoints.TokenAuth.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.TokenAuth.Tests.Web.Data;

public class MyDbContext : IdentityDbContext
{
    public DbSet<Token<string, IdentityUser>>? GetTokens { get; set; }
    public DbSet<RefreshToken>? GetRefreshTokens { get; set; }

    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
    {
    }
}
