using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;

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
        Assert.Equal(HttpStatusCode.Forbidden, reauthResponse.StatusCode);
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
        HttpResponseMessage? login = null;
        for (var attempt = 0; attempt < 6; attempt++)
        {
            login = await client.PostAsJsonAsync("/identity/login", new
            {
                email,
                password = TestHelpers.DefaultPassword,
                twoFactorRecoveryCode = codes[0]
            });
            if (login.StatusCode != HttpStatusCode.TooManyRequests)
            {
                break;
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        Assert.True(
            login!.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
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

    [Fact]
    public async Task ConfirmIdentity_WrongPassword_IncrementsAccessFailedCount()
    {
        var email = $"reauth-lockout-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var confirmResponse = await TestHelpers.PostWithCsrfAsync(
            client,
            "/identity/confirmIdentity",
            new { password = "WrongPass1!" });
        Assert.Equal(HttpStatusCode.Unauthorized, confirmResponse.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var tracked = await userManager.FindByIdAsync(user.Id);
        Assert.NotNull(tracked);
        Assert.True(await userManager.GetAccessFailedCountAsync(tracked) > 0);
    }

    [Fact]
    public async Task ConfirmIdentity_ReturnsReauthToken()
    {
        var email = $"reauth-token-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var token = await TestHelpers.ConfirmIdentityAsync(
            client,
            new { password = TestHelpers.DefaultPassword });
        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public async Task RequireReauthOnly_Anonymous_IsUnauthorized()
    {
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        var response = await client.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RequireReauthOnly_ReauthCredentialWithoutSignIn_IsRejected()
    {
        var email = $"reauth-alone-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var issuer = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(issuer, email, TestHelpers.DefaultPassword);
        var reauth = await TestHelpers.ConfirmIdentityAsync(
            issuer,
            new { password = TestHelpers.DefaultPassword });

        using var proofOnly = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        TestHelpers.SetReauthToken(proofOnly, reauth);
        var alone = await proofOnly.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.Unauthorized, alone.StatusCode);
    }

    [Fact]
    public async Task ConfirmIdentity_CookieSignIn_SetsReAuthCookie()
    {
        var email = $"reauth-set-cookie-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var jar = new CookieJar();

        HttpResponseMessage? loginResponse = null;
        for (var attempt = 0; attempt < 6; attempt++)
        {
            using var login = new HttpRequestMessage(HttpMethod.Post, "/identity/login")
            {
                Content = JsonContent.Create(new { email, password = TestHelpers.DefaultPassword })
            };
            loginResponse = await client.SendAsync(login);
            if (loginResponse.StatusCode != HttpStatusCode.TooManyRequests)
            {
                break;
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        Assert.True(
            loginResponse!.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
            $"Login failed: {(int)loginResponse.StatusCode}");
        jar.Collect(loginResponse);

        using var csrfRequest = new HttpRequestMessage(HttpMethod.Get, "/identity/csrfToken");
        jar.Apply(csrfRequest);
        var csrfResponse = await client.SendAsync(csrfRequest);
        Assert.Equal(HttpStatusCode.OK, csrfResponse.StatusCode);
        jar.Collect(csrfResponse);
        using var csrfDoc = JsonDocument.Parse(await csrfResponse.Content.ReadAsStringAsync());
        var csrf = csrfDoc.RootElement.TryGetProperty("csrfToken", out var csrfCamel)
            ? csrfCamel.GetString()
            : csrfDoc.RootElement.GetProperty("CsrfToken").GetString();

        using var confirm = new HttpRequestMessage(HttpMethod.Post, "/identity/confirmIdentity")
        {
            Content = JsonContent.Create(new { password = TestHelpers.DefaultPassword })
        };
        confirm.Headers.Add("RequestVerificationToken", csrf);
        jar.Apply(confirm);
        var confirmResponse = await client.SendAsync(confirm);
        Assert.Equal(HttpStatusCode.OK, confirmResponse.StatusCode);
        Assert.True(SetsReAuthCookie(confirmResponse));
    }

    [Fact]
    public async Task ConfirmIdentity_BearerHeader_ReturnsTokenWithoutReAuthCookie()
    {
        var email = $"reauth-bearer-nocookie-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var (accessToken, _) = await TestHelpers.LoginBearerAsync(client, email, TestHelpers.DefaultPassword);
        TestHelpers.SetBearer(client, accessToken);

        var confirm = await client.PostAsJsonAsync(
            "/identity/bearer/confirmIdentity",
            new { password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        Assert.False(SetsReAuthCookie(confirm));

        using var doc = JsonDocument.Parse(await confirm.Content.ReadAsStringAsync());
        var token = TestHelpers.TryGetString(doc.RootElement, "reauthToken", "ReauthToken");
        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public async Task SecurityStampChange_RejectsReAuthCookie()
    {
        var email = $"reauth-stamp-cookie-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        await TestHelpers.ConfirmIdentityAsync(client, new { password = TestHelpers.DefaultPassword });

        var before = await client.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        await UpdateSecurityStampAsync(email);

        var after = await client.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.Forbidden, after.StatusCode);
    }

    [Theory]
    [InlineData("identity-bearer")]
    [InlineData("jwt")]
    public async Task SecurityStampChange_RejectsReAuthToken(string signIn)
    {
        var email = $"reauth-stamp-token-{signIn}-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var accessToken = signIn == "jwt"
            ? await TestHelpers.CreateJwtAsync(client, email, TestHelpers.DefaultPassword)
            : (await TestHelpers.LoginBearerAsync(client, email, TestHelpers.DefaultPassword)).AccessToken;
        TestHelpers.SetBearer(client, accessToken);

        var confirmPath = signIn == "jwt" ? "/identity/confirmIdentity" : "/identity/bearer/confirmIdentity";
        var confirm = await client.PostAsJsonAsync(confirmPath, new { password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        Assert.False(SetsReAuthCookie(confirm));
        using var doc = JsonDocument.Parse(await confirm.Content.ReadAsStringAsync());
        var reauth = TestHelpers.TryGetString(doc.RootElement, "reauthToken", "ReauthToken");
        Assert.False(string.IsNullOrWhiteSpace(reauth));
        TestHelpers.SetReauthToken(client, reauth!);

        var managePath = signIn == "jwt" ? "/identity/manage/info" : "/identity/bearer/manage/info";
        var before = await client.PostAsJsonAsync(managePath, new { });
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        await UpdateSecurityStampAsync(email);

        var after = await client.PostAsJsonAsync(managePath, new { });
        Assert.Equal(HttpStatusCode.Forbidden, after.StatusCode);
    }

    [Fact]
    public async Task ReAuthProof_WithoutSecurityStamp_IsRejected()
    {
        var email = $"reauth-no-stamp-{Guid.NewGuid():N}@test.local";
        var seeded = await TestHelpers.SeedUserAsync(_factory, email);

        string token;
        using (var scope = _factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = await users.FindByIdAsync(seeded.Id);
            Assert.NotNull(user);
            var tokens = scope.ServiceProvider.GetRequiredService<ReAuthTokenService>();
            token = tokens.CreateToken(
            [
                new Claim("Reauth", "true"),
                new Claim("ReauthTime", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new Claim(users.Options.ClaimsIdentity.UserIdClaimType, await users.GetUserIdAsync(user)),
            ]);
        }

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        TestHelpers.SetReauthToken(client, token);

        var response = await client.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private async Task UpdateSecurityStampAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await users.FindByEmailAsync(email);
        Assert.NotNull(user);
        var updated = await users.UpdateSecurityStampAsync(user);
        Assert.True(updated.Succeeded, string.Join("; ", updated.Errors.Select(error => error.Description)));
    }

    private static bool SetsReAuthCookie(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return false;
        }

        return values.Any(value => value.Contains($"{AuthEndpointsConstants.ReAuthScheme}=", StringComparison.Ordinal));
    }

    private sealed class CookieJar
    {
        private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

        public void Collect(HttpResponseMessage response)
        {
            if (!response.Headers.TryGetValues("Set-Cookie", out var values))
            {
                return;
            }

            foreach (var value in values)
            {
                var pair = value.Split(';', 2)[0];
                var separator = pair.IndexOf('=');
                if (separator <= 0)
                {
                    continue;
                }

                var name = pair[..separator].Trim();
                var cookieValue = pair[(separator + 1)..].Trim();
                if (cookieValue.Length == 0)
                {
                    _cookies.Remove(name);
                }
                else
                {
                    _cookies[name] = cookieValue;
                }
            }
        }

        public void Apply(HttpRequestMessage request)
        {
            if (_cookies.Count == 0)
            {
                return;
            }

            request.Headers.TryAddWithoutValidation(
                "Cookie",
                string.Join("; ", _cookies.Select(cookie => $"{cookie.Key}={cookie.Value}")));
        }
    }
}
