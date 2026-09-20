using System.Net;
using System.Threading;
using AuthEndpoints;
using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests;

public class ReAuthLifetimeTests
{
    private static readonly DateTimeOffset FrozenUtc = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Options_DefaultLifetime_IsFiveMinutes()
    {
        Assert.Equal(TimeSpan.FromMinutes(5), new AuthEndpointsReAuthOptions().Lifetime);
        Assert.Equal(TimeSpan.FromMinutes(5), new AuthEndpointsOptions().ReAuth.Lifetime);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(61)]
    public void Validator_RejectsOutOfRangeMinutes(int minutes)
    {
        var result = new AuthEndpointsReAuthOptionsValidator().Validate(
            null,
            new AuthEndpointsReAuthOptions { Lifetime = TimeSpan.FromMinutes(minutes) });
        Assert.True(result.Failed);
    }

    [Fact]
    public void Validator_RejectsThirtySeconds()
    {
        var result = new AuthEndpointsReAuthOptionsValidator().Validate(
            null,
            new AuthEndpointsReAuthOptions { Lifetime = TimeSpan.FromSeconds(30) });
        Assert.True(result.Failed);
        Assert.Contains("1 minute", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validator_RejectsInfiniteTimeSpan()
    {
        var result = new AuthEndpointsReAuthOptionsValidator().Validate(
            null,
            new AuthEndpointsReAuthOptions { Lifetime = Timeout.InfiniteTimeSpan });
        Assert.True(result.Failed);
        Assert.Contains("InfiniteTimeSpan", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(60)]
    public void Validator_AcceptsRange(int minutes)
    {
        var result = new AuthEndpointsReAuthOptionsValidator().Validate(
            null,
            new AuthEndpointsReAuthOptions { Lifetime = TimeSpan.FromMinutes(minutes) });
        Assert.False(result.Failed);
    }

    [Fact]
    public void ComposableHost_DefaultLifetime_DrivesCookieExpireTimeSpan()
    {
        using var app = BuildComposableHost();
        var reauth = app.Services.GetRequiredService<IOptions<AuthEndpointsReAuthOptions>>().Value;
        var cookie = app.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(AuthEndpointsConstants.ReAuthScheme);

        Assert.Equal(TimeSpan.FromMinutes(5), reauth.Lifetime);
        Assert.Equal(TimeSpan.FromMinutes(5), cookie.ExpireTimeSpan);
        Assert.False(cookie.SlidingExpiration);
    }

    [Fact]
    public void ComposableHost_CustomLifetime_DrivesCookieExpireTimeSpan()
    {
        using var app = BuildComposableHost(TimeSpan.FromMinutes(2));
        var reauth = app.Services.GetRequiredService<IOptions<AuthEndpointsReAuthOptions>>().Value;
        var cookie = app.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(AuthEndpointsConstants.ReAuthScheme);

        Assert.Equal(TimeSpan.FromMinutes(2), reauth.Lifetime);
        Assert.Equal(TimeSpan.FromMinutes(2), cookie.ExpireTimeSpan);
        Assert.False(cookie.SlidingExpiration);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(61)]
    public void ComposableHost_InvalidLifetime_FailsOptionsValidation(int minutes)
    {
        using var app = BuildComposableHost(TimeSpan.FromMinutes(minutes));
        var ex = Assert.ThrowsAny<Exception>(() =>
            _ = app.Services.GetRequiredService<IOptions<AuthEndpointsReAuthOptions>>().Value);
        Assert.Contains("ReAuth.Lifetime", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Facade_Configure_DrivesCookieAndTokenLifetime()
    {
        var lifetime = TimeSpan.FromMinutes(2);
        await using var host = await StartFacadeHostAsync(o => o.ReAuth.Lifetime = lifetime);

        var reauth = host.Services.GetRequiredService<IOptions<AuthEndpointsReAuthOptions>>().Value;
        var cookie = host.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(AuthEndpointsConstants.ReAuthScheme);

        Assert.Equal(lifetime, host.Services.GetRequiredService<IOptions<AuthEndpointsOptions>>().Value.ReAuth.Lifetime);
        Assert.Equal(lifetime, reauth.Lifetime);
        Assert.Equal(lifetime, cookie.ExpireTimeSpan);
        Assert.False(cookie.SlidingExpiration);
    }

    [Fact]
    public async Task DefaultLifetime_CookieAndToken_ExpireAfterFiveMinutes()
    {
        var time = new MutableTimeProvider(FrozenUtc);
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateTimedFactory(root, time);

        await AssertLifetimeAsync(factory, time, TimeSpan.FromMinutes(5));
    }

    [Fact]
    public async Task CustomTwoMinuteLifetime_CookieAndToken_UseTwoMinutes()
    {
        var time = new MutableTimeProvider(FrozenUtc);
        var lifetime = TimeSpan.FromMinutes(2);
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateTimedFactory(root, time, lifetime);

        var cookie = factory.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(AuthEndpointsConstants.ReAuthScheme);
        Assert.Equal(lifetime, cookie.ExpireTimeSpan);

        await AssertLifetimeAsync(factory, time, lifetime);
    }

    [Fact]
    public async Task ConfirmIdentity_ReAuthCookie_IsNotPersistent()
    {
        await using var factory = new TestWebApplicationFactory();
        var email = $"reauth-persist-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);

        using var client = TestHelpers.CreateClientWithCookies(factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var confirm = await TestHelpers.PostWithCsrfAsync(
            client,
            "/identity/confirmIdentity",
            new { password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);

        Assert.True(confirm.Headers.TryGetValues("Set-Cookie", out var setCookies));
        var reauthCookie = setCookies.FirstOrDefault(v =>
            v.StartsWith(AuthEndpointsConstants.ReAuthScheme + "=", StringComparison.OrdinalIgnoreCase));
        Assert.False(string.IsNullOrEmpty(reauthCookie), "Expected AuthEndpoints.ReAuth Set-Cookie.");
        Assert.DoesNotContain("expires=", reauthCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("max-age=", reauthCookie, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task AssertLifetimeAsync(
        WebApplicationFactory<Program> factory,
        MutableTimeProvider time,
        TimeSpan lifetime)
    {
        var email = $"reauth-life-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);

        using var client = TestHelpers.CreateClientWithCookies(factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var token = await TestHelpers.ConfirmIdentityAsync(
            client,
            new { password = TestHelpers.DefaultPassword });

        var tokenService = factory.Services.GetRequiredService<ReAuthTokenService>();
        Assert.NotNull(tokenService.Unprotect(token));

        var beforeExpiry = await client.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.OK, beforeExpiry.StatusCode);

        time.Advance(lifetime - TimeSpan.FromSeconds(1));
        Assert.NotNull(tokenService.Unprotect(token));
        var stillValid = await client.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.OK, stillValid.StatusCode);

        time.Advance(TimeSpan.FromSeconds(2));
        Assert.Null(tokenService.Unprotect(token));

        var expiredCookie = await client.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.Unauthorized, expiredCookie.StatusCode);

        using var headerClient = TestHelpers.CreateClientWithCookies(factory);
        await TestHelpers.LoginCookieAsync(headerClient, email, TestHelpers.DefaultPassword);
        TestHelpers.SetReauthToken(headerClient, token);
        var expiredHeader = await headerClient.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.Unauthorized, expiredHeader.StatusCode);
    }

    private static WebApplicationFactory<Program> CreateTimedFactory(
        TestWebApplicationFactory root,
        MutableTimeProvider time,
        TimeSpan? lifetime = null)
    {
        return root.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(time);
                if (lifetime is { } value)
                {
                    services.Configure<AuthEndpointsReAuthOptions>(o => o.Lifetime = value);
                }
            });
        });
    }

    private static WebApplication BuildComposableHost(TimeSpan? lifetime = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.WebHost.UseTestServer();
        if (lifetime is { } value)
        {
            builder.Services.Configure<AuthEndpointsReAuthOptions>(o => o.Lifetime = value);
        }

        builder.Services.AddReAuthScheme();
        return builder.Build();
    }

    private static async Task<WebApplication> StartFacadeHostAsync(Action<AuthEndpointsOptions> configure)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(o =>
            o.UseInMemoryDatabase("ReAuthLifetimeFacade_" + Guid.NewGuid().ToString("N")));
        builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(o =>
        {
            o.Passkeys.ServerDomain = "localhost";
            o.ConfigureIdentity = identity =>
            {
                identity.SignIn.RequireConfirmedAccount = false;
            };
            configure(o);
        });
        builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();

        var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            await db.Database.EnsureCreatedAsync();
        }

        app.UseAuthEndpoints();
        app.MapAuthEndpoints<TestAppUser>();
        await app.StartAsync();
        return app;
    }

    private sealed class MutableTimeProvider : TimeProvider
    {
        public MutableTimeProvider(DateTimeOffset utcNow)
        {
            UtcNow = utcNow;
        }

        public DateTimeOffset UtcNow { get; private set; }

        public override DateTimeOffset GetUtcNow() => UtcNow;

        public void Advance(TimeSpan delta) => UtcNow += delta;
    }
}
