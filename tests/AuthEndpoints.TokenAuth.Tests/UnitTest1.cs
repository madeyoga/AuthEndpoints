using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthEndpoints.Core.Contracts;
using AuthEndpoints.TokenAuth.Tests.Web.Contracts;

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
