using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests;

public sealed class BodyRefreshApplicationFactory : TestWebApplicationFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("AE_JWT_REFRESH_TRANSPORT", "Body");
        builder.ConfigureAppConfiguration(static (_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AE_JWT_REFRESH_TRANSPORT"] = "Body",
            });
        });
    }
}

public sealed class SplitBodyRefreshApplicationFactory : TestWebApplicationFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("AE_HOST_MODE", "split");
        builder.UseSetting("AE_JWT_REFRESH_TRANSPORT", "Body");
        builder.ConfigureAppConfiguration(static (_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AE_HOST_MODE"] = "split",
                ["AE_JWT_REFRESH_TRANSPORT"] = "Body",
            });
        });
    }
}

public class JwtRefreshHardeningTests :
    IClassFixture<TestWebApplicationFactory>,
    IClassFixture<BodyRefreshApplicationFactory>,
    IClassFixture<SplitBodyRefreshApplicationFactory>
{
    private readonly TestWebApplicationFactory _cookie;
    private readonly BodyRefreshApplicationFactory _body;
    private readonly SplitBodyRefreshApplicationFactory _split;

    public JwtRefreshHardeningTests(
        TestWebApplicationFactory cookie,
        BodyRefreshApplicationFactory body,
        SplitBodyRefreshApplicationFactory split)
    {
        _cookie = cookie;
        _body = body;
        _split = split;
    }

    [Fact]
    public async Task Body_CreateVerifyRefreshLogout_SendsNoCookies()
    {
        var email = $"jwt-body-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_body, email);
        using var client = NoCookies(_body);

        var create = await PostJson(client, "/auth/create", new { email, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        AssertNoRefreshCookie(create);
        var created = await ReadTokenAsync(create);
        Assert.False(string.IsNullOrWhiteSpace(created.Access));
        Assert.Equal("Bearer", created.Type);
        Assert.False(string.IsNullOrWhiteSpace(created.Refresh));

        using (var verifyRequest = new HttpRequestMessage(HttpMethod.Get, "/auth/verify"))
        {
            verifyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", created.Access);
            var verify = await client.SendAsync(verifyRequest);
            Assert.Equal(HttpStatusCode.NoContent, verify.StatusCode);
        }

        var csrf = await client.GetAsync("/auth/csrfToken");
        Assert.Equal(HttpStatusCode.NotFound, csrf.StatusCode);

        var refresh = await PostJson(client, "/auth/refresh", new { refreshToken = created.Refresh });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        AssertNoRefreshCookie(refresh);
        var rotated = await ReadTokenAsync(refresh);
        Assert.False(string.IsNullOrWhiteSpace(rotated.Access));
        Assert.Equal("Bearer", rotated.Type);
        Assert.NotEqual(created.Refresh, rotated.Refresh);

        var logout = await PostJson(client, "/auth/logout", new { refreshToken = rotated.Refresh });
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        var again = await PostJson(client, "/auth/refresh", new { refreshToken = rotated.Refresh });
        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);

        var rows = await TokensAsync(_body, user.Id);
        Assert.NotEmpty(rows);
        Assert.All(rows, row => Assert.NotNull(row.RevokedAt));
    }

    [Fact]
    public async Task Body_Replay_RevokesFamily()
    {
        var email = $"jwt-body-replay-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_body, email);
        using var client = NoCookies(_body);

        var create = await PostJson(client, "/auth/create", new { email, password = TestHelpers.DefaultPassword });
        var created = await ReadTokenAsync(create);
        var refresh = await PostJson(client, "/auth/refresh", new { refreshToken = created.Refresh });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        var rotated = await ReadTokenAsync(refresh);

        var replay = await PostJson(client, "/auth/refresh", new { refreshToken = created.Refresh });
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);

        var successor = await PostJson(client, "/auth/refresh", new { refreshToken = rotated.Refresh });
        Assert.Equal(HttpStatusCode.BadRequest, successor.StatusCode);

        var rows = await TokensAsync(_body, user.Id);
        Assert.Contains(rows, row => row.ReplacedByTokenId != null);
        Assert.All(rows, row => Assert.NotNull(row.RevokedAt));
        Assert.Equal(rows[0].AbsoluteExpiresAt, rows[^1].AbsoluteExpiresAt);
    }

    [Fact]
    public async Task Body_IgnoresCookie_AndRejectsMissingOrUnknownToken()
    {
        var email = $"jwt-body-fail-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_body, email);
        using var client = NoCookies(_body);

        var create = await PostJson(client, "/auth/create", new { email, password = TestHelpers.DefaultPassword });
        var created = await ReadTokenAsync(create);

        using var cookieOnly = new HttpRequestMessage(HttpMethod.Post, "/auth/refresh");
        cookieOnly.Headers.TryAddWithoutValidation(
            "Cookie",
            $"{RefreshTokenCookieWriter.CookieName}={created.Refresh}");
        cookieOnly.Content = JsonContent.Create(new { });
        var ignored = await client.SendAsync(cookieOnly);
        Assert.Equal(HttpStatusCode.BadRequest, ignored.StatusCode);
        Assert.Contains("Missing refresh token.", await ignored.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var unknown = await PostJson(client, "/auth/refresh", new { refreshToken = "not-a-real-token" });
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        Assert.Contains("Invalid refresh token", await unknown.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var logout = await PostJson(client, "/auth/logout", new { });
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
    }

    [Fact]
    public async Task Body_WrongContentType_Returns415_AndLeavesTheTokenUsable()
    {
        var email = $"jwt-body-ctype-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_body, email);
        using var client = NoCookies(_body);
        var create = await PostJson(client, "/auth/create", new { email, password = TestHelpers.DefaultPassword });
        var created = await ReadTokenAsync(create);

        using var refresh = new HttpRequestMessage(HttpMethod.Post, "/auth/refresh")
        {
            Content = new StringContent("refresh-token", System.Text.Encoding.UTF8, "text/plain"),
        };
        var wrongRefresh = await client.SendAsync(refresh);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, wrongRefresh.StatusCode);

        using var logout = new HttpRequestMessage(HttpMethod.Post, "/auth/logout")
        {
            Content = new StringContent("refresh-token", System.Text.Encoding.UTF8, "text/plain"),
        };
        var wrongLogout = await client.SendAsync(logout);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, wrongLogout.StatusCode);

        var rows = await TokensAsync(_body, user.Id);
        Assert.Single(rows);
        Assert.Null(rows[0].RevokedAt);

        var again = await PostJson(client, "/auth/refresh", new { refreshToken = created.Refresh });
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
    }

    [Fact]
    public async Task Body_StampChange_RevokesFamily()
    {
        var email = $"jwt-body-stamp-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_body, email);
        using var client = NoCookies(_body);
        var create = await PostJson(client, "/auth/create", new { email, password = TestHelpers.DefaultPassword });
        var created = await ReadTokenAsync(create);

        using (var scope = _body.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var tracked = await userManager.FindByIdAsync(user.Id);
            Assert.NotNull(tracked);
            var change = await userManager.ChangePasswordAsync(tracked, TestHelpers.DefaultPassword, "NewPassw0rd!");
            Assert.True(change.Succeeded);
        }

        var refresh = await PostJson(client, "/auth/refresh", new { refreshToken = created.Refresh });
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
        var rows = await TokensAsync(_body, user.Id);
        Assert.All(rows, row => Assert.NotNull(row.RevokedAt));
    }

    [Fact]
    public async Task Body_EmailCodeVerify_ReturnsRefreshToken()
    {
        var email = $"jwt-verify-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_split, email);
        using var client = NoCookies(_split);

        var send = await PostJson(client, "/emailCode/send", new { email });
        Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        var code = await CodeAsync(client, email);

        var verify = await PostJson(client, "/app/emailCode/verify", new { email, code });
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
        AssertNoRefreshCookie(verify);
        var created = await ReadTokenAsync(verify);
        Assert.False(string.IsNullOrWhiteSpace(created.Access));
        Assert.Equal("Bearer", created.Type);
        Assert.False(string.IsNullOrWhiteSpace(created.Refresh));

        var refresh = await PostJson(client, "/app/refresh", new { refreshToken = created.Refresh });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        var rotated = await ReadTokenAsync(refresh);
        Assert.NotEqual(created.Refresh, rotated.Refresh);

        using var access = new HttpRequestMessage(HttpMethod.Get, "/app/verify");
        access.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rotated.Access);
        var verified = await client.SendAsync(access);
        Assert.Equal(HttpStatusCode.NoContent, verified.StatusCode);

        var csrf = await client.GetAsync("/app/csrfToken");
        Assert.Equal(HttpStatusCode.NotFound, csrf.StatusCode);
    }

    [Fact]
    public async Task Cookie_Replay_RevokesFamily_AndJsonOmitsRefreshToken()
    {
        var email = $"jwt-cookie-replay-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_cookie, email);
        var jar = new CookieJarHandler();
        using var client = _cookie.CreateDefaultClient(jar);
        TestHelpers.AttachWebAuthnOrigin(client);

        var create = await PostJson(client, "/auth/create", new { email, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        await AssertNoRefreshTokenPropertyAsync(create);
        Assert.True(create.Headers.TryGetValues("Set-Cookie", out var issuedCookies));
        var oldCookie = jar.Cookies.GetCookies(client.BaseAddress!)[RefreshTokenCookieWriter.CookieName]?.Value;
        Assert.False(string.IsNullOrEmpty(oldCookie));

        var refresh = await TestHelpers.PostWithCsrfAsync(
            client, "/auth/refresh", body: null, csrfPath: "/auth/csrfToken");
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        await AssertNoRefreshTokenPropertyAsync(refresh);
        var newCookie = jar.Cookies.GetCookies(client.BaseAddress!)[RefreshTokenCookieWriter.CookieName]?.Value;
        Assert.False(string.IsNullOrEmpty(newCookie));
        Assert.NotEqual(oldCookie, newCookie);

        // Replay the original Set-Cookie through a cookie jar. A raw Cookie.Value
        // header drops the antiforgery cookie and can disagree with the jar's encoding.
        var replayJar = new CookieJarHandler();
        foreach (var issued in issuedCookies)
        {
            replayJar.Cookies.SetCookies(client.BaseAddress!, issued);
        }

        using var replayClient = _cookie.CreateDefaultClient(replayJar);
        TestHelpers.AttachWebAuthnOrigin(replayClient);
        var replay = await TestHelpers.PostWithCsrfAsync(
            replayClient, "/auth/refresh", body: null, csrfPath: "/auth/csrfToken");
        Assert.True(
            replay.StatusCode == HttpStatusCode.BadRequest,
            $"replay {(int)replay.StatusCode} {await replay.Content.ReadAsStringAsync()}");

        var again = await TestHelpers.PostWithCsrfAsync(
            client, "/auth/refresh", body: null, csrfPath: "/auth/csrfToken");
        Assert.True(
            again.StatusCode == HttpStatusCode.BadRequest,
            $"again {(int)again.StatusCode} {await again.Content.ReadAsStringAsync()}");

        var rows = await TokensAsync(_cookie, user.Id);
        Assert.Contains(rows, row => row.ReplacedByTokenId != null);
        Assert.All(rows, row => Assert.NotNull(row.RevokedAt));
    }

    [Fact]
    public async Task Cookie_StampChange_RevokesFamily()
    {
        var email = $"jwt-cookie-stamp-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_cookie, email);
        using var client = TestHelpers.CreateClientWithCookies(_cookie);
        var create = await PostJson(client, "/auth/create", new { email, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);

        using (var scope = _cookie.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var tracked = await userManager.FindByIdAsync(user.Id);
            Assert.NotNull(tracked);
            var stamp = await userManager.UpdateSecurityStampAsync(tracked);
            Assert.True(stamp.Succeeded, string.Join("; ", stamp.Errors.Select(error => error.Description)));
        }

        var refresh = await TestHelpers.PostWithCsrfAsync(
            client, "/auth/refresh", body: null, csrfPath: "/auth/csrfToken");
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);

        var rows = await TokensAsync(_cookie, user.Id);
        Assert.NotEmpty(rows);
        Assert.All(rows, row => Assert.NotNull(row.RevokedAt));
    }

    [Fact]
    public async Task Cookie_Logout_RevokesFamilyOnTheServer()
    {
        var email = $"jwt-cookie-logout-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_cookie, email);
        using var client = TestHelpers.CreateClientWithCookies(_cookie);
        var create = await PostJson(client, "/auth/create", new { email, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);

        var logout = await TestHelpers.PostWithCsrfAsync(
            client, "/auth/logout", body: null, csrfPath: "/auth/csrfToken");
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        var rows = await TokensAsync(_cookie, user.Id);
        Assert.NotEmpty(rows);
        Assert.All(rows, row => Assert.NotNull(row.RevokedAt));
    }

    [Fact]
    public async Task AbsoluteLifetime_IsNotExtendedByRefresh_AndThenRejects()
    {
        await using var factory = new AbsoluteLifetimeApplicationFactory();
        var email = $"jwt-absolute-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(factory, email);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var create = await PostJson(client, "/auth/create", new { email, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        factory.Clock.Advance(TimeSpan.FromMinutes(1));

        var refresh = await TestHelpers.PostWithCsrfAsync(
            client, "/auth/refresh", body: null, csrfPath: "/auth/csrfToken");
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);

        var rows = await TokensAsync(factory, user.Id);
        Assert.Equal(2, rows.Count);
        Assert.All(rows, row => Assert.Equal(rows[0].AbsoluteExpiresAt, row.AbsoluteExpiresAt));
        var successor = rows.Single(row => row.RevokedAt == null);
        Assert.Equal(successor.AbsoluteExpiresAt, successor.ExpiresAt);

        factory.Clock.Advance(TimeSpan.FromMinutes(4));
        var expired = await TestHelpers.PostWithCsrfAsync(
            client, "/auth/refresh", body: null, csrfPath: "/auth/csrfToken");
        Assert.Equal(HttpStatusCode.BadRequest, expired.StatusCode);

        var after = await TokensAsync(factory, user.Id);
        Assert.Equal(2, after.Count);
        Assert.Contains(after, row => row.RevokedAt == null);
    }

    [Fact]
    public async Task Service_Rotation_KeepsAbsoluteExpiry_AndJoinDoesNotRestartIt()
    {
        var email = $"jwt-svc-abs-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_cookie, email);
        var clock = new MutableClock(new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero));

        using var scope = _cookie.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var tracked = await userManager.FindByIdAsync(user.Id);
        Assert.NotNull(tracked);
        var stamp = await userManager.GetSecurityStampAsync(tracked);
        var service = new RefreshTokenService<TestDbContext>(
            db,
            clock,
            Options.Create(new JwtSessionOptions
            {
                RefreshTokenLifetime = TimeSpan.FromDays(14),
                AbsoluteLifetime = TimeSpan.FromHours(1),
            }));

        var issued = await service.CreateAsync(user.Id, stamp);
        Assert.Equal(clock.GetUtcNow().UtcDateTime.AddHours(1), issued.AbsoluteExpiresAt);
        Assert.Equal(issued.AbsoluteExpiresAt, issued.ExpiresAt);
        Assert.True(service.IsValid(issued));

        clock.Advance(TimeSpan.FromMinutes(10));
        var rotated = await service.RotateAsync(issued, stamp);
        Assert.NotNull(rotated);
        Assert.Equal(issued.AbsoluteExpiresAt, rotated.AbsoluteExpiresAt);
        Assert.Equal(issued.AbsoluteExpiresAt, rotated.ExpiresAt);

        var joined = await service.CreateAsync(user.Id, stamp, issued.FamilyId);
        Assert.Equal(issued.AbsoluteExpiresAt, joined.AbsoluteExpiresAt);

        clock.Advance(TimeSpan.FromMinutes(51));
        Assert.False(service.IsValid(rotated));
        Assert.Null(await service.RotateAsync(rotated, stamp));
        var stillThere = await db.Set<RefreshToken>().SingleAsync(row => row.Id == rotated.Id);
        Assert.Null(stillThere.RevokedAt);
    }

    [Fact]
    public void JwtSessionOptions_RejectsNonPositiveLifetimeAndUnknownTransport()
    {
        var validator = new JwtSessionOptionsValidator();
        var lifetime = validator.Validate(null, new JwtSessionOptions { AbsoluteLifetime = TimeSpan.Zero });
        Assert.True(lifetime.Failed);
        Assert.Contains(lifetime.Failures!, failure => failure.Contains("AbsoluteLifetime", StringComparison.Ordinal));

        var window = validator.Validate(null, new JwtSessionOptions { RefreshTokenLifetime = TimeSpan.Zero });
        Assert.True(window.Failed);

        var transport = validator.Validate(null, new JwtSessionOptions
        {
            RefreshTokenTransport = (RefreshTokenTransport)9,
        });
        Assert.True(transport.Failed);
    }

    [Fact]
    public void RefreshToken_Model_RequiresAbsoluteExpiresAt()
    {
        using var scope = _cookie.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        var property = db.Model.FindEntityType(typeof(RefreshToken))!
            .FindProperty(nameof(RefreshToken.AbsoluteExpiresAt));
        Assert.NotNull(property);
        Assert.False(property.IsNullable);
    }

    private static HttpClient NoCookies(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false,
        });
        TestHelpers.AttachWebAuthnOrigin(client);
        return client;
    }

    private static async Task<HttpResponseMessage> PostJson(HttpClient client, string path, object body)
    {
        for (var attempt = 0; attempt < 6; attempt++)
        {
            var response = await client.PostAsJsonAsync(path, body);
            if (response.StatusCode != HttpStatusCode.TooManyRequests)
            {
                return response;
            }

            response.Dispose();
            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        return await client.PostAsJsonAsync(path, body);
    }

    private static async Task<TokenBody> ReadTokenAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return new TokenBody(
            TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken"),
            TestHelpers.TryGetString(doc.RootElement, "refreshToken", "RefreshToken"),
            TestHelpers.TryGetString(doc.RootElement, "tokenType", "TokenType"));
    }

    private static async Task AssertNoRefreshTokenPropertyAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(doc.RootElement.TryGetProperty("refreshToken", out _));
        Assert.False(doc.RootElement.TryGetProperty("RefreshToken", out _));
    }

    private static void AssertNoRefreshCookie(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return;
        }

        Assert.DoesNotContain(
            values,
            value => value.Contains(RefreshTokenCookieWriter.CookieName, StringComparison.Ordinal));
    }

    private static string? RefreshCookie(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return null;
        }

        var prefix = RefreshTokenCookieWriter.CookieName + "=";
        foreach (var header in values)
        {
            var start = header.IndexOf(prefix, StringComparison.Ordinal);
            if (start < 0)
            {
                continue;
            }

            var rest = header[(start + prefix.Length)..];
            var end = rest.IndexOf(';');
            return end >= 0 ? rest[..end] : rest;
        }

        return null;
    }

    private static async Task<List<RefreshToken>> TokensAsync(WebApplicationFactory<Program> factory, string userId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        return await db.Set<RefreshToken>().Where(row => row.UserId == userId).OrderBy(row => row.ExpiresAt).ToListAsync();
    }

    private static async Task<string> CodeAsync(HttpClient client, string email)
    {
        var response = await client.GetAsync("/test/mailbox");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        foreach (var item in doc.RootElement.EnumerateArray())
        {
            var itemEmail = TestHelpers.TryGetString(item, "email", "Email");
            var kind = TestHelpers.TryGetString(item, "kind", "Kind");
            if (string.Equals(itemEmail, email, StringComparison.Ordinal)
                && string.Equals(kind, "email-code", StringComparison.Ordinal))
            {
                var code = TestHelpers.TryGetString(item, "body", "Body");
                Assert.False(string.IsNullOrWhiteSpace(code));
                return code!;
            }
        }

        throw new Xunit.Sdk.XunitException($"No email-code for {email}.");
    }

    private sealed record TokenBody(string? Access, string? Refresh, string? Type);

    private sealed class AbsoluteLifetimeApplicationFactory : TestWebApplicationFactory
    {
        public MutableClock Clock { get; } = new(DateTimeOffset.UtcNow);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(Clock);
                services.Configure<JwtSessionOptions>(options =>
                {
                    options.AbsoluteLifetime = TimeSpan.FromMinutes(5);
                    options.RefreshTokenLifetime = TimeSpan.FromDays(14);
                });
            });
        }
    }

    private sealed class MutableClock : TimeProvider
    {
        private DateTimeOffset _utc;

        public MutableClock(DateTimeOffset utc)
        {
            _utc = utc;
        }

        public override DateTimeOffset GetUtcNow() => _utc;

        public void Advance(TimeSpan by) => _utc = _utc.Add(by);
    }

    private sealed class CookieJarHandler : DelegatingHandler
    {
        public System.Net.CookieContainer Cookies { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var uri = request.RequestUri ?? throw new InvalidOperationException("Request URI is missing.");
            var header = Cookies.GetCookieHeader(uri);
            if (!string.IsNullOrEmpty(header))
            {
                request.Headers.TryAddWithoutValidation("Cookie", header);
            }

            var response = await base.SendAsync(request, cancellationToken);
            if (response.Headers.TryGetValues("Set-Cookie", out var values))
            {
                foreach (var value in values)
                {
                    Cookies.SetCookies(uri, value);
                }
            }

            return response;
        }
    }

}
