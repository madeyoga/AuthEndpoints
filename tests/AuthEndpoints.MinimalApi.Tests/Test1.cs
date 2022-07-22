using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthEndpoints.Demo.Data;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
//using Microsoft.VisualStudio.TestPlatform.TestHost;

namespace AuthEndpoints.MinimalApi.Tests;

public class Test1
{
    [Fact]
    public async Task Can_RegisterUser()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "test@developerblogs.id",
            Username = "developerblogsid",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Cannot_RegisterDuplicateUsername()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "test1@test.id",
            Username = "duplicateusername",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });

        var response = await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "test2@test.id",
            Username = "duplicateusername",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task Cannot_RegisterDuplicateEmail()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "duplicateemail@test.id",
            Username = "duplicateemail1",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });

        var response = await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "duplicateemail@test.id",
            Username = "duplicateemail2",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task Can_CreateJwt()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        var registerResp = await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "user1@test.id",
            Username = "user1",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });
        Assert.Equal(HttpStatusCode.OK, registerResp.StatusCode);

        var response = await client.PostAsJsonAsync("/jwt/create", new LoginRequest
        {
            Username = "user1",
            Password = "testtest"
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GetLoggedInUserData()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "user2@test.id",
            Username = "user2",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });

        var response1 = await client.PostAsJsonAsync("/jwt/create", new LoginRequest
        {
            Username = "user2",
            Password = "testtest"
        });

        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);

        var result = await response1.Content.ReadFromJsonAsync<AuthenticatedUserResponse>();
        Assert.NotNull(result);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result!.AccessToken!);
        var response2 = await client.GetAsync("/users/me");
        Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
    }

    [Fact]
    public async Task Can_RefreshJwt()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "refresh1@test.id",
            Username = "refresh1",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });

        var response1 = await client.PostAsJsonAsync("/jwt/create", new LoginRequest
        {
            Username = "refresh1",
            Password = "testtest"
        });

        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);

        var result = await response1.Content.ReadFromJsonAsync<AuthenticatedUserResponse>();
        Assert.NotNull(result);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result!.AccessToken!);
        var response2 = await client.PostAsJsonAsync("/jwt/refresh", new RefreshRequest
        {
            RefreshToken = result!.RefreshToken!,
        });
        Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
    }

    [Fact]
    public async Task Can_VerifyJwt()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "verify1@test.id",
            Username = "verify1",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });

        var response1 = await client.PostAsJsonAsync("/jwt/create", new LoginRequest
        {
            Username = "verify1",
            Password = "testtest"
        });

        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);

        var result = await response1.Content.ReadFromJsonAsync<AuthenticatedUserResponse>();
        Assert.NotNull(result);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result!.AccessToken!);
        var response2 = await client.GetAsync("/jwt/verify");
        Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
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
