using AuthEndpoints.Demo.Data;
using AuthEndpoints.SimpleJwt;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
//using Microsoft.VisualStudio.TestPlatform.TestHost;

namespace AuthEndpoints.Tests;

class AuthApplication : WebApplicationFactory<Program>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        var root = new InMemoryDatabaseRoot();

        builder.ConfigureServices(services =>
        {
            services.RemoveAll(typeof(DbContextOptions<MyDbContext>));

            services.AddDbContext<MyDbContext>(options =>
            {
                options.UseInMemoryDatabase("Testing", root);
                options.UseSimpleJwtEntities();
            });
        });

        return base.CreateHost(builder);
    }
}
