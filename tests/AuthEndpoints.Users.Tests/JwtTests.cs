using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthEndpoints.SimpleJwt;

namespace AuthEndpoints.Tests;

public class JwtTests
{
    [Fact]
    public async Task CreateJwt()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync("/jwt/create", new SimpleJwtLoginRequest
        {
            Username = "test",
            Password = "testtest"
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CreateJwt_InvalidCredentials_Unauthorized()
    {
        await using var application = new AuthApplication();
        var client = application.CreateClient();

        var response = await client.PostAsJsonAsync("/jwt/create", new SimpleJwtLoginRequest
        {
            Username = "test",
            Password = "wrongpassword"
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var response2 = await client.PostAsJsonAsync("/jwt/create", new SimpleJwtLoginRequest
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

        var response1 = await client.PostAsJsonAsync("/jwt/create", new SimpleJwtLoginRequest
        {
            Username = "test",
            Password = "testtest"
        });

        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);

        var result = await response1.Content.ReadFromJsonAsync<SimpleJwtTokenResponse>();
        Assert.NotNull(result);

        var response2 = await client.PostAsJsonAsync("/jwt/refresh", new SimpleJwtRefreshTokenRequest
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

        var response = await client.PostAsJsonAsync("/jwt/refresh", new SimpleJwtRefreshTokenRequest
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

        var response1 = await client.PostAsJsonAsync("/jwt/create", new SimpleJwtLoginRequest
        {
            Username = "test",
            Password = "testtest"
        });

        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);

        var result = await response1.Content.ReadFromJsonAsync<SimpleJwtTokenResponse>();
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
