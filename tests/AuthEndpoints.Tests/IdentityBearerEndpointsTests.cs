using System.Net;
using System.Text.Json;

namespace AuthEndpoints.Tests;

public class IdentityBearerEndpointsTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public IdentityBearerEndpointsTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Login_ReturnsAccessAndRefreshTokens()
    {
        var email = $"bearer-login-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = _factory.CreateClient();

        var (accessToken, refreshToken) = await TestHelpers.LoginBearerAsync(
            client,
            email,
            TestHelpers.DefaultPassword);

        Assert.False(string.IsNullOrWhiteSpace(accessToken));
        Assert.False(string.IsNullOrWhiteSpace(refreshToken));
    }

    [Fact]
    public async Task Login_UseCookies_SucceedsWithoutJsonTokens()
    {
        var email = $"bearer-cookie-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.PostAsJsonAsync(
            "/identity/bearer/login?useCookies=true",
            new { email, password = TestHelpers.DefaultPassword });

        Assert.True(response.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent);

        var info = await client.GetAsync("/identity/bearer/manage/info");
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);
    }

    [Fact]
    public async Task Refresh_ValidToken_ReturnsNewTokens()
    {
        var email = $"bearer-refresh-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = _factory.CreateClient();

        var (_, refreshToken) = await TestHelpers.LoginBearerAsync(
            client,
            email,
            TestHelpers.DefaultPassword);

        var refresh = await client.PostAsJsonAsync("/identity/bearer/refresh", new { refreshToken });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);

        using var doc = JsonDocument.Parse(await refresh.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrWhiteSpace(
            TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken")));
        Assert.False(string.IsNullOrWhiteSpace(
            TestHelpers.TryGetString(doc.RootElement, "refreshToken", "RefreshToken")));
    }

    [Fact]
    public async Task Refresh_GarbageToken_ReturnsUnauthorized()
    {
        using var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/identity/bearer/refresh",
            new { refreshToken = "not-a-real-refresh-token" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Register_ThenLogin_ThenManageInfo_Succeeds()
    {
        var email = $"bearer-reg-{Guid.NewGuid():N}@test.local";
        using var client = _factory.CreateClient();

        var register = await client.PostAsJsonAsync("/identity/bearer/register", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var (accessToken, _) = await TestHelpers.LoginBearerAsync(
            client,
            email,
            TestHelpers.DefaultPassword);
        TestHelpers.SetBearer(client, accessToken);

        var info = await client.GetAsync("/identity/bearer/manage/info");
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);

        using var doc = JsonDocument.Parse(await info.Content.ReadAsStringAsync());
        Assert.Equal(email, TestHelpers.TryGetString(doc.RootElement, "email", "Email"));
    }

    [Fact]
    public async Task Logout_Authorized_Succeeds()
    {
        var email = $"bearer-logout-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = _factory.CreateClient();

        var (accessToken, _) = await TestHelpers.LoginBearerAsync(
            client,
            email,
            TestHelpers.DefaultPassword);
        TestHelpers.SetBearer(client, accessToken);

        var logout = await client.PostAsync("/identity/bearer/logout", content: null);
        Assert.True(logout.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task ManageInfoPost_WithBearer_SucceedsWithoutCsrf()
    {
        var email = $"bearer-info-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        const string newPassword = "BearerChanged1!";
        using var client = _factory.CreateClient();

        var (accessToken, _) = await TestHelpers.LoginBearerAsync(
            client,
            email,
            TestHelpers.DefaultPassword);
        TestHelpers.SetBearer(client, accessToken);

        var response = await client.PostAsJsonAsync("/identity/bearer/manage/info", new
        {
            oldPassword = TestHelpers.DefaultPassword,
            newPassword
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        client.DefaultRequestHeaders.Authorization = null;
        var (newAccess, _) = await TestHelpers.LoginBearerAsync(client, email, newPassword);
        Assert.False(string.IsNullOrWhiteSpace(newAccess));
    }
}
