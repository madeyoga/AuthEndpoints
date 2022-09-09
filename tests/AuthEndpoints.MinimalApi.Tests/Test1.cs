using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.SimpleJwt.Contracts;

namespace AuthEndpoints.MinimalApi.Tests;

public class Test1
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
    public async Task CreateJwt()
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
    public async Task CreateJwt_InvalidCredentials_Unauthorized()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        var registerResp = await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "CreateJwt_InvalidCredentials@test.id",
            Username = "InvalidCredentials",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });
        Assert.Equal(HttpStatusCode.OK, registerResp.StatusCode);

        var response = await client.PostAsJsonAsync("/jwt/create", new LoginRequest
        {
            Username = "InvalidCredentials1",
            Password = "wrongpassword"
        });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var response2 = await client.PostAsJsonAsync("/jwt/create", new LoginRequest
        {
            Username = "wrongusername",
            Password = "testtest"
        });
        Assert.Equal(HttpStatusCode.Unauthorized, response2.StatusCode);
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

    [Fact]
    public async Task RefreshJwt()
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

        var response2 = await client.PostAsJsonAsync("/jwt/refresh", new RefreshRequest
        {
            RefreshToken = result!.RefreshToken!,
        });
        Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
    }

    [Fact]
    public async Task RefreshJwt_InvalidToken_BadRequest()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();

        var response = await client.PostAsJsonAsync("/jwt/refresh", new RefreshRequest
        {
            RefreshToken = "RandomToken",
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task VerifyJwt()
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
        Assert.Equal(HttpStatusCode.NoContent, response2.StatusCode);
    }

    [Fact]
    public async Task VerifyJwt_InvalidToken_Unauthorized()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "RandomToken");
        var response2 = await client.GetAsync("/jwt/verify");
        Assert.Equal(HttpStatusCode.Unauthorized, response2.StatusCode);
    }
}
