using System.Net;
using System.Text.Json;

namespace AuthEndpoints.Tests;

public class ReAuthEndpointsTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public ReAuthEndpointsTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task AuthMethods_AfterLogin_ReportsPassword()
    {
        var email = $"reauth-methods-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var response = await client.GetAsync("/identity/manage/authMethods");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        var password = root.TryGetProperty("password", out var p) ? p.GetBoolean() : root.GetProperty("Password").GetBoolean();
        Assert.True(password);
    }

    [Fact]
    public async Task ConfirmIdentity_WithPassword_IssuesReAuthCookie()
    {
        var email = $"reauth-confirm-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var confirmResponse = await TestHelpers.PostWithCsrfAsync(
            client,
            "/identity/confirmIdentity",
            new { password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, confirmResponse.StatusCode);

        var reauthResponse = await client.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.OK, reauthResponse.StatusCode);
    }

    [Fact]
    public async Task ConfirmIdentity_WrongPassword_DoesNotIssueReAuthCookie()
    {
        var email = $"reauth-wrong-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var confirmResponse = await TestHelpers.PostWithCsrfAsync(
            client,
            "/identity/confirmIdentity",
            new { password = "WrongPass1!" });
        Assert.NotEqual(HttpStatusCode.OK, confirmResponse.StatusCode);

        var reauthResponse = await client.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.Unauthorized, reauthResponse.StatusCode);
    }

    [Fact]
    public async Task ConfirmIdentity_Unauthenticated_ReturnsUnauthorized()
    {
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var csrf = await TestHelpers.GetCsrfTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/identity/confirmIdentity")
        {
            Content = JsonContent.Create(new { password = TestHelpers.DefaultPassword })
        };
        request.Headers.Add("RequestVerificationToken", csrf);

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ConfirmIdentity_WithRecoveryCode_IssuesReAuthCookie()
    {
        var email = $"reauth-recovery-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email, twoFactorEnabled: true);
        var codes = await TestHelpers.GenerateRecoveryCodesAsync(_factory, user);
        Assert.NotEmpty(codes);

        using var client = TestHelpers.CreateClientWithCookies(_factory);

        // Cookie login with recovery code after password step requires two-factor recovery on login.
        var login = await client.PostAsJsonAsync("/identity/login", new
        {
            email,
            password = TestHelpers.DefaultPassword,
            twoFactorRecoveryCode = codes[0]
        });
        Assert.True(
            login.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
            $"Login with recovery failed: {(int)login.StatusCode} {await login.Content.ReadAsStringAsync()}");

        // Use a fresh recovery code for ReAuth (first code was consumed at login).
        var remaining = await TestHelpers.GenerateRecoveryCodesAsync(_factory, user);
        var confirm = await TestHelpers.PostWithCsrfAsync(
            client,
            "/identity/confirmIdentity",
            new { twoFactorRecoveryCode = remaining[0] });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);

        var reauthResponse = await client.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.OK, reauthResponse.StatusCode);
    }
}
