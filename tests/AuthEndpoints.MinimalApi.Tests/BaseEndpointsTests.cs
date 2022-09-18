using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.SimpleJwt.Contracts;

namespace AuthEndpoints.MinimalApi.Tests;

public class BaseEndpointsTests
{
    [Fact]
    public async Task CreateUser()
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
    public async Task CreateUser_InvalidEmail_Conflict()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "invalidEmail",
            Username = "invalidEmail",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task CreateUser_ConfirmPasswordNotMatch_BadRequest()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "passwordNotMatch@test.com",
            Username = "passwordNotMatch",
            Password = "test1",
            ConfirmPassword = "test2",
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task CreateUser_DuplicateUsername_Conflict()
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
    public async Task CreateUser_DuplicateEmail_Conflict()
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
    public async Task GetLoggedInUserData_Authorized()
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
    public async Task GetLoggedInUserData_Unauthorized()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        var response2 = await client.GetAsync("/users/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response2.StatusCode);
    }
}
