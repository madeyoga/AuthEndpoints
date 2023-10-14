using AuthEndpoints.Demo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Demo.Data;

public class MyDbContext : IdentityDbContext<MyCustomIdentityUser>
{
    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
    }
}

public class UserDataSeeder
{
    private readonly UserManager<MyCustomIdentityUser> userManager;

    public UserDataSeeder(UserManager<MyCustomIdentityUser> userManager)
    {
        this.userManager = userManager;
    }

    public void Populate()
    {
        var user = new MyCustomIdentityUser
        {
            Id = "02174cf0–9412–4cfe-afbf-59f706d72cf6",
            UserName = "test",
            Email = "test@example.com",
            EmailConfirmed = true,
            PhoneNumber = "1234567890"
        };

        userManager.CreateAsync(user, "testtest").Wait();
    }
}
