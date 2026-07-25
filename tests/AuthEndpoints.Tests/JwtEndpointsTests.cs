using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Tests;

public class JwtEndpointsTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public JwtEndpointsTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Create_WithoutTwoFactor_ReturnsAccessToken()
    {
        var email = $"jwt-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = _factory.CreateClient();
        var response = await PostCreateAllowingRateLimitAsync(client, email, TestHelpers.DefaultPassword);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(
            doc.RootElement.TryGetProperty("accessToken", out var token)
            || doc.RootElement.TryGetProperty("AccessToken", out token));
        Assert.False(string.IsNullOrWhiteSpace(token.GetString()));
    }

    [Fact]
    public async Task Create_WrongPassword_Returns401()
    {
        var email = $"jwt-bad-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = _factory.CreateClient();
        var response = await PostCreateAllowingRateLimitAsync(client, email, "WrongPassword!");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Invalid credentials", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Create_Lockout_IncrementsAccessFailed()
    {
        var email = $"jwt-lock-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = _factory.CreateClient();
        var response = await PostCreateAllowingRateLimitAsync(client, email, "WrongPassword!");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        Assert.NotNull(user);
        Assert.True(user.AccessFailedCount > 0 || await userManager.IsLockedOutAsync(user));
    }

    [Fact]
    public async Task Create_WithTwoFactorEnabledAndNoCode_ReturnsRequiresTwoFactor()
    {
        var email = $"jwt2fa-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email, twoFactorEnabled: true);

        using var client = _factory.CreateClient();
        var response = await PostCreateAllowingRateLimitAsync(client, email, TestHelpers.DefaultPassword);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("requiresTwoFactor", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Create_WithTwoFactorCode_Succeeds()
    {
        var email = $"jwt2fa-ok-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email, twoFactorEnabled: true);
        var code = await TestHelpers.GenerateAuthenticatorCodeAsync(_factory, user);

        using var client = _factory.CreateClient();
        var response = await PostCreateAllowingRateLimitAsync(
            client, email, TestHelpers.DefaultPassword, twoFactorCode: code);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_RotatesToken_AndRejectsOldCookie()
    {
        var email = $"jwt-refresh-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        var create = await PostCreateAllowingRateLimitAsync(client, email, TestHelpers.DefaultPassword);
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);

        var firstRefresh = await TestHelpers.PostWithCsrfAsync(
            client, "/auth/refresh", body: null, csrfPath: "/auth/csrfToken");
        Assert.Equal(HttpStatusCode.OK, firstRefresh.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        var tokens = await db.Set<RefreshToken>().ToListAsync();
        var revoked = tokens.FirstOrDefault(t => t.RevokedAt != null && t.ReplacedByTokenId != null);
        Assert.NotNull(revoked);

        var familyId = revoked.FamilyId;
        var validInFamily = await db.Set<RefreshToken>()
            .CountAsync(t => t.FamilyId == familyId && t.RevokedAt == null);
        Assert.Equal(1, validInFamily);
    }

    [Fact]
    public async Task Refresh_WithoutCsrf_Returns400()
    {
        var email = $"jwt-csrf-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        var create = await PostCreateAllowingRateLimitAsync(client, email, TestHelpers.DefaultPassword);
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);

        var refresh = await client.PostAsync("/auth/refresh", null);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
    }

    [Fact]
    public async Task Refresh_AfterPasswordChange_IsRejected()
    {
        var email = $"jwt-stamp-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        var create = await PostCreateAllowingRateLimitAsync(client, email, TestHelpers.DefaultPassword);
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var tracked = await userManager.FindByIdAsync(user.Id);
            Assert.NotNull(tracked);
            var change = await userManager.ChangePasswordAsync(
                tracked, TestHelpers.DefaultPassword, "NewPassw0rd!");
            Assert.True(change.Succeeded);
        }

        var refresh = await TestHelpers.PostWithCsrfAsync(
            client, "/auth/refresh", body: null, csrfPath: "/auth/csrfToken");
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
    }

    [Fact]
    public async Task Logout_RevokesRefreshFamily()
    {
        var email = $"jwt-logout-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        var create = await PostCreateAllowingRateLimitAsync(client, email, TestHelpers.DefaultPassword);
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);

        var logout = await TestHelpers.PostWithCsrfAsync(
            client, "/auth/logout", body: null, csrfPath: "/auth/csrfToken");
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        var refresh = await TestHelpers.PostWithCsrfAsync(
            client, "/auth/refresh", body: null, csrfPath: "/auth/csrfToken");
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
    }

    private static async Task<HttpResponseMessage> PostCreateAllowingRateLimitAsync(
        HttpClient client,
        string email,
        string password,
        string? twoFactorCode = null)
    {
        for (var attempt = 0; attempt < 6; attempt++)
        {
            var response = await client.PostAsJsonAsync("/auth/create", new
            {
                email,
                password,
                twoFactorCode
            });
            if (response.StatusCode != HttpStatusCode.TooManyRequests)
            {
                return response;
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        return await client.PostAsJsonAsync("/auth/create", new { email, password, twoFactorCode });
    }

    [Fact]
    public void OptionsValidator_RequiresSymmetricKey()
    {
        var options = new SimpleJwtOptions
        {
            SigningOptions = new SimpleJwtSigningOptions
            {
                Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Symmetric,
                SymmetricKey = null
            }
        };

        var result = new SimpleJwtOptionsValidator().Validate(nameof(SimpleJwtOptions), options);
        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("SymmetricKey", StringComparison.Ordinal));
    }

    [Fact]
    public void OptionsValidator_RejectsShortSymmetricKey()
    {
        var options = new SimpleJwtOptions
        {
            SigningOptions = new SimpleJwtSigningOptions
            {
                Algorithm = SimpleJwtSigningOptions.SigningAlgorithm.Symmetric,
                SymmetricKey = "too-short"
            }
        };

        var result = new SimpleJwtOptionsValidator().Validate(nameof(SimpleJwtOptions), options);
        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("256", StringComparison.Ordinal));
    }
}
