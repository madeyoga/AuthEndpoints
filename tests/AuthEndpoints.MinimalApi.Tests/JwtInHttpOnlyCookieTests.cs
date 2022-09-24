using System.Net;
using System.Net.Http.Json;
using AuthEndpoints.Core.Contracts;

namespace AuthEndpoints.MinimalApi.Tests;

public class JwtInHttpOnlyCookieTests
{
    [Fact]
    public async Task CreateJwtCookie()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        var registerResp = await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "user_jwtcookie@test.id",
            Username = "user_jwtcookie",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });
        Assert.Equal(HttpStatusCode.OK, registerResp.StatusCode);

        var response = await client.PostAsJsonAsync("/jwt/cookie/create", new LoginRequest
        {
            Username = "user_jwtcookie",
            Password = "testtest"
        });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task CreateJwtCookie_InvalidCredentials_Unauthorized()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        var registerResp = await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "CreateJwt_InvalidCredentials@test.id",
            Username = "InvalidCredentialsJwtCookie",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });
        Assert.Equal(HttpStatusCode.OK, registerResp.StatusCode);

        var response = await client.PostAsJsonAsync("/jwt/cookie/create", new LoginRequest
        {
            Username = "InvalidCredentialsJwtCookie",
            Password = "wrongpassword"
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var response2 = await client.PostAsJsonAsync("/jwt/cookie/create", new LoginRequest
        {
            Username = "wrongusername",
            Password = "testtest"
        });
        Assert.Equal(HttpStatusCode.BadRequest, response2.StatusCode);
    }

    [Fact]
    public async Task RefreshJwtCookie()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "refresh1@test.id",
            Username = "refresh2",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });

        var response1 = await client.PostAsJsonAsync("/jwt/cookie/create", new LoginRequest
        {
            Username = "refresh2",
            Password = "testtest"
        });
        Assert.Equal(HttpStatusCode.NoContent, response1.StatusCode);
        var response2 = await client.GetAsync("/jwt/cookie/refresh");
        Assert.Equal(HttpStatusCode.NoContent, response2.StatusCode);
    }

    [Fact]
    public async Task VerifyJwtCookie()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        await client.PostAsJsonAsync("/users", new RegisterRequest
        {
            Email = "verify3@test.id",
            Username = "verify3",
            Password = "testtest",
            ConfirmPassword = "testtest",
        });

        var response1 = await client.PostAsJsonAsync("/jwt/cookie/create", new LoginRequest
        {
            Username = "verify3",
            Password = "testtest"
        });

        Assert.Equal(HttpStatusCode.NoContent, response1.StatusCode);

        var response2 = await client.GetAsync("/jwt/cookie/verify");
        Assert.Equal(HttpStatusCode.NoContent, response2.StatusCode);
    }
}
