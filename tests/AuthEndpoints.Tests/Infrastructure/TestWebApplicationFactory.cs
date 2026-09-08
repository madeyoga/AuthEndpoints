using Microsoft.AspNetCore.Mvc.Testing;

namespace AuthEndpoints.Tests;

public class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _dbName = "AuthEndpointsTests_" + Guid.NewGuid().ToString("N");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.UseContentRoot(AppContext.BaseDirectory);
        // UseSetting is applied early enough for WebApplication.CreateBuilder config reads.
        builder.UseSetting("TestDbName", _dbName);
        builder.UseSetting("AE_REQUIRE_CONFIRMED_ACCOUNT", "false");
        builder.UseSetting("AE_CONFIRM_EMAIL_REDIRECT_URI", "");
        builder.UseSetting("AE_CONFIRM_EMAIL_ALLOWED_ORIGINS", "");
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TestDbName"] = _dbName,
                ["AE_REQUIRE_CONFIRMED_ACCOUNT"] = "false",
                ["AE_CONFIRM_EMAIL_REDIRECT_URI"] = "",
                ["AE_CONFIRM_EMAIL_ALLOWED_ORIGINS"] = ""
            });
        });
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseContentRoot(AppContext.BaseDirectory);
        return base.CreateHost(builder);
    }
}
