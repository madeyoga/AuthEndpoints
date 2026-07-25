using System.Net;
using System.Text.Json;

namespace AuthEndpoints.Tests;

public class IdentityCookieEndpointsTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public IdentityCookieEndpointsTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Register_ValidRequest_CreatesUser()
    {
        var email = $"reg-{Guid.NewGuid():N}@test.local";
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.PostAsJsonAsync("/identity/register", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var user = await TestHelpers.FindUserByEmailAsync(_factory, email);
        Assert.NotNull(user);
        Assert.Equal(email, user.Email);
    }

    [Fact]
    public async Task Register_InvalidEmail_ReturnsValidationProblem()
    {
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.PostAsJsonAsync("/identity/register", new
        {
            email = "not-an-email",
            password = TestHelpers.DefaultPassword
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_DuplicateEmail_ReturnsValidationProblem()
    {
        var email = $"dup-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.PostAsJsonAsync("/identity/register", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Login_ValidCredentials_Succeeds()
    {
        var email = $"login-ok-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.PostAsJsonAsync("/identity/login", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });

        Assert.True(response.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent);

        var info = await client.GetAsync("/identity/manage/info");
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);
    }

    [Fact]
    public async Task Login_WrongPassword_ReturnsUnauthorized()
    {
        var email = $"login-bad-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.PostAsJsonAsync("/identity/login", new
        {
            email,
            password = "WrongPass1!"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_TwoFactorEnabledWithoutCode_ReturnsRequiresTwoFactor()
    {
        var email = $"login-2fa-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email, twoFactorEnabled: true);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.PostAsJsonAsync("/identity/login", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("RequiresTwoFactor", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CsrfToken_ReturnsToken()
    {
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.GetAsync("/identity/csrfToken");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var token = TestHelpers.TryGetString(doc.RootElement, "csrfToken", "CsrfToken");
        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public async Task Logout_WithCsrf_ClearsSession()
    {
        var email = $"logout-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var logout = await TestHelpers.PostWithCsrfAsync(client, "/identity/logout", body: null);
        Assert.True(logout.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent);

        var info = await client.GetAsync("/identity/manage/info");
        Assert.Equal(HttpStatusCode.Unauthorized, info.StatusCode);
    }

    [Fact]
    public async Task Logout_WithoutCsrf_ReturnsBadRequest()
    {
        var email = $"logout-csrf-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var response = await client.PostAsync("/identity/logout", content: null);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ManageInfo_Unauthenticated_ReturnsUnauthorized()
    {
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.GetAsync("/identity/manage/info");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
