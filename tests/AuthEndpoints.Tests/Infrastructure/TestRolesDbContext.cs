using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Tests;

public class TestRolesDbContext : IdentityDbContext<TestAppUser, IdentityRole, string>
{
    public TestRolesDbContext(DbContextOptions<TestRolesDbContext> options)
        : base(options)
    {
    }
}
