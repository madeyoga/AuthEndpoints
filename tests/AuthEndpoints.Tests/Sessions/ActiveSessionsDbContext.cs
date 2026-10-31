using AuthEndpoints.EmailCode;
using AuthEndpoints.Jwt;
using AuthEndpoints.Sessions;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Tests.Sessions;

public class ActiveSessionsDbContext : IdentityDbContext<TestAppUser>
{
    public ActiveSessionsDbContext(DbContextOptions<ActiveSessionsDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.UseRefreshToken();
        builder.UseEmailCodes();
        builder.UseActiveSessions();
    }
}
