using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

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

    [Fact]
    public async Task IdentityBearerHeader_WithoutCsrf_Succeeds()
    {
        var email = $"csrf-idbearer-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = _factory.CreateClient();
        var (accessToken, _) = await TestHelpers.LoginBearerAsync(client, email, TestHelpers.DefaultPassword);
        TestHelpers.SetBearer(client, accessToken);

        var response = await client.PostAsync("/test/csrf-auth", content: null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ApplicationCookieAndBearerHeader_WithoutCsrf_IsChecked()
    {
        var email = $"csrf-both-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        var accessToken = await TestHelpers.CreateJwtAsync(client, email, TestHelpers.DefaultPassword);
        TestHelpers.SetBearer(client, accessToken);

        var response = await client.PostAsync("/test/csrf-auth", content: null);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("CSRF", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task JwtHeader_WithRefreshCookie_WithoutCsrf_Succeeds()
    {
        var email = $"csrf-refresh-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        HttpResponseMessage? create = null;
        for (var attempt = 0; attempt < 6; attempt++)
        {
            create = await client.PostAsJsonAsync(
                "/auth/create",
                new { email, password = TestHelpers.DefaultPassword });
            if (create.StatusCode != HttpStatusCode.TooManyRequests)
            {
                break;
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        create!.EnsureSuccessStatusCode();
        Assert.True(create.Headers.TryGetValues("Set-Cookie", out var setCookies));
        Assert.Contains(
            setCookies,
            static cookie => cookie.Contains("AuthEndpoints.Jwt.RefreshToken", StringComparison.Ordinal));
        using var created = JsonDocument.Parse(await create.Content.ReadAsStringAsync());
        var accessToken = TestHelpers.TryGetString(created.RootElement, "accessToken", "AccessToken");
        Assert.False(string.IsNullOrEmpty(accessToken));
        TestHelpers.SetBearer(client, accessToken!);

        var response = await client.PostAsync("/test/csrf-auth", content: null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
