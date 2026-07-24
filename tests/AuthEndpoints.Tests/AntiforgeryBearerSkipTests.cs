using System.Net;
using System.Net.Http.Json;

namespace AuthEndpoints.Tests;

public class AntiforgeryBearerSkipTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public AntiforgeryBearerSkipTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Anonymous_CsrfProtectedEndpoint_WithoutToken_Returns400()
    {
        using var client = _factory.CreateClient();
        var response = await client.PostAsync("/test/csrf", content: null);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("CSRF", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task BearerOnly_CsrfProtectedAuthorizedEndpoint_WithoutToken_Succeeds()
    {
        var email = $"csrf-bearer-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = _factory.CreateClient();
        var accessToken = await TestHelpers.CreateJwtAsync(client, email, TestHelpers.DefaultPassword);
        TestHelpers.SetBearer(client, accessToken);

        var response = await client.PostAsync("/test/csrf-auth", content: null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CookieAuth_CsrfProtectedAuthorizedEndpoint_WithoutToken_Fails()
    {
        var email = $"csrf-cookie-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var response = await client.PostAsync("/test/csrf-auth", content: null);
        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }
}
