using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.SimpleJwt.Contracts;

namespace AuthEndpoints.MinimalApi.Tests;

public class JwtTests
{
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
            Username = "InvalidCredentials",
            Password = "wrongpassword"
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var response2 = await client.PostAsJsonAsync("/jwt/create", new LoginRequest
        {
            Username = "wrongusername",
            Password = "testtest"
        });
        Assert.Equal(HttpStatusCode.BadRequest, response2.StatusCode);
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
