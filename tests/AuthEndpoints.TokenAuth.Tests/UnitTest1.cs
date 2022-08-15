using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.TokenAuth.Tests.Web.Contracts;
using AuthEndpoints.TokenAuth.Tests.Web.Data;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.TokenAuth.Tests;

public class UnitTest1
{
    [Fact]
    public async Task Create_AuthToken()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();

        await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "test@developerblogs.id",
            Username = "test",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });

        var response = await client.PostAsJsonAsync("/token/login", new LoginRequest
        {
            Username = "test",
            Password = "testtest",
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Destroy_AuthToken()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();

        await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "test@developerblogs.id",
            Username = "test",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });

        var response = await client.PostAsJsonAsync("/token/login", new LoginRequest
        {
            Username = "test",
            Password = "testtest",
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var result = await response.Content.ReadFromJsonAsync<TokenAuthResponse>();
        Assert.NotNull(result);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result!.AuthToken!);

        var response2 = await client.PostAsJsonAsync("/token/logout", new { });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}

class AuthApplication : WebApplicationFactory<Program>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        var root = new InMemoryDatabaseRoot();

        builder.ConfigureServices(services =>
        {
            services.RemoveAll(typeof(DbContextOptions<MyDbContext>));

            services.AddDbContext<MyDbContext>(options =>
                options.UseInMemoryDatabase("Testing", root));
        });

        return base.CreateHost(builder);
    }
}
