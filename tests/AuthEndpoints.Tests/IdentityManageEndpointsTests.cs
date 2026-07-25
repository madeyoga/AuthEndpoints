using System.Net;
using System.Text.Json;

namespace AuthEndpoints.Tests;

public class IdentityManageEndpointsTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public IdentityManageEndpointsTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task ManageInfoGet_AfterLogin_ReturnsEmail()
    {
        var email = $"info-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var response = await client.GetAsync("/identity/manage/info");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(email, TestHelpers.TryGetString(doc.RootElement, "email", "Email"));
        Assert.True(TestHelpers.TryGetBool(doc.RootElement, "isEmailConfirmed", "IsEmailConfirmed", out var confirmed));
        Assert.True(confirmed);
    }

    [Fact]
    public async Task ManageInfoPost_WithoutReAuth_IsUnauthorized()
    {
        var email = $"pwd-noreauth-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var response = await TestHelpers.PostWithCsrfAsync(client, "/identity/manage/info", new
        {
            oldPassword = TestHelpers.DefaultPassword,
            newPassword = "ChangedPass1!"
        });

        Assert.True(
            response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
            $"Expected 401/403 without ReAuth, got {(int)response.StatusCode}");
    }

    [Fact]
    public async Task ManageInfoPost_ChangePassword_Succeeds()
    {
        var email = $"pwd-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        const string newPassword = "ChangedPass1!";
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        await TestHelpers.ConfirmIdentityAsync(client, new { password = TestHelpers.DefaultPassword });

        var response = await TestHelpers.PostWithCsrfAsync(client, "/identity/manage/info", new
        {
            oldPassword = TestHelpers.DefaultPassword,
            newPassword
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var fresh = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(fresh, email, newPassword);
    }

    [Fact]
    public async Task ManageInfoPost_NewPasswordWithoutOld_ReturnsValidationProblem()
    {
        var email = $"pwd-old-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        await TestHelpers.ConfirmIdentityAsync(client, new { password = TestHelpers.DefaultPassword });

        var response = await TestHelpers.PostWithCsrfAsync(client, "/identity/manage/info", new
        {
            newPassword = "ChangedPass1!"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("OldPasswordRequired", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TwoFactorStatus_ReportsDisabledByDefault()
    {
        var email = $"2fa-status-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var response = await client.GetAsync("/identity/manage/2fa");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(TestHelpers.TryGetBool(doc.RootElement, "isTwoFactorEnabled", "IsTwoFactorEnabled", out var enabled));
        Assert.False(enabled);
    }

    [Fact]
    public async Task ManageTwoFactor_WithoutReAuth_IsForbiddenOrUnauthorized()
    {
        var email = $"2fa-noreauth-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var response = await TestHelpers.PostWithCsrfAsync(client, "/identity/manage/2fa", new
        {
            enable = true,
            twoFactorCode = "000000"
        });

        Assert.True(
            response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
            $"Expected 401/403 without ReAuth, got {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
    }

    [Fact]
    public async Task ManageTwoFactor_WithReAuth_EnablesTwoFactor()
    {
        var email = $"2fa-enable-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        await TestHelpers.ConfirmIdentityAsync(client, new { password = TestHelpers.DefaultPassword });

        // Probe manage/2fa to mint a shared key when missing (exposed because key was just created).
        var probe = await TestHelpers.PostWithCsrfAsync(client, "/identity/manage/2fa", new { });
        Assert.Equal(HttpStatusCode.OK, probe.StatusCode);

        using var probeDoc = JsonDocument.Parse(await probe.Content.ReadAsStringAsync());
        var sharedKey = TestHelpers.TryGetString(probeDoc.RootElement, "sharedKey", "SharedKey");
        Assert.False(string.IsNullOrWhiteSpace(sharedKey));

        await TestHelpers.ConfirmIdentityAsync(client, new { password = TestHelpers.DefaultPassword });

        var code = TotpHelper.GenerateCode(sharedKey!);
        var enable = await TestHelpers.PostWithCsrfAsync(client, "/identity/manage/2fa", new
        {
            enable = true,
            twoFactorCode = code
        });
        Assert.True(
            enable.StatusCode == HttpStatusCode.OK,
            $"Enable 2FA failed: {(int)enable.StatusCode} {await enable.Content.ReadAsStringAsync()}");

        using var doc = JsonDocument.Parse(await enable.Content.ReadAsStringAsync());
        Assert.True(TestHelpers.TryGetBool(doc.RootElement, "isTwoFactorEnabled", "IsTwoFactorEnabled", out var enabled));
        Assert.True(enabled);

        Assert.True(
            doc.RootElement.TryGetProperty("recoveryCodes", out var codes)
            || doc.RootElement.TryGetProperty("RecoveryCodes", out codes));
        Assert.Equal(JsonValueKind.Array, codes.ValueKind);
        Assert.True(codes.GetArrayLength() > 0);

        var keyFromManager = await TestHelpers.GetAuthenticatorKeyAsync(_factory, user);
        Assert.Equal(sharedKey, keyFromManager);
    }
}
