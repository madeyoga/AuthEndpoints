using System.Net;
using System.Text.Json;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.Tests;

public class ReAuthProofRenewalTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public ReAuthProofRenewalTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Theory]
    [InlineData("identity-bearer")]
    [InlineData("jwt")]
    public async Task ManageTwoFactor_HeaderProof_IsRenewedInResponseHeader(string signIn)
    {
        var email = $"renew-header-{signIn}-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var paths = await SignInWithHeaderProofAsync(client, email, signIn);
        var original = client.DefaultRequestHeaders.GetValues(AuthEndpointsConstants.ReAuthHeaderName).Single();

        var reset = await client.PostAsJsonAsync(paths.TwoFactor, new { resetSharedKey = true });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        Assert.False(SetsReAuthCookie(reset));
        var renewed = RenewedHeader(reset);
        Assert.NotNull(renewed);
        Assert.NotEqual(original, renewed);
        var sharedKey = await SharedKeyAsync(reset);

        // The proof sent before the change no longer matches the account.
        var stale = await client.PostAsJsonAsync(paths.TwoFactor, new { enable = true, twoFactorCode = TotpHelper.GenerateCode(sharedKey) });
        Assert.Equal(HttpStatusCode.Forbidden, stale.StatusCode);

        TestHelpers.SetReauthToken(client, renewed!);
        var enable = await client.PostAsJsonAsync(paths.TwoFactor, new { enable = true, twoFactorCode = TotpHelper.GenerateCode(sharedKey) });
        Assert.Equal(HttpStatusCode.OK, enable.StatusCode);
        var renewedAgain = RenewedHeader(enable);
        Assert.NotNull(renewedAgain);

        TestHelpers.SetReauthToken(client, renewedAgain!);
        var info = await client.PostAsJsonAsync(paths.Info, new { });
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);
    }

    [Fact]
    public async Task ManageTwoFactor_CookieProof_IsRenewedWithoutResponseHeader()
    {
        var email = $"renew-cookie-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        await TestHelpers.ConfirmIdentityAsync(client, new { password = TestHelpers.DefaultPassword });

        var reset = await TestHelpers.PostWithCsrfAsync(client, "/identity/manage/2fa", new { resetSharedKey = true });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        Assert.True(SetsReAuthCookie(reset));
        Assert.Null(RenewedHeader(reset));
        var sharedKey = await SharedKeyAsync(reset);

        var enable = await TestHelpers.PostWithCsrfAsync(client, "/identity/manage/2fa", new
        {
            enable = true,
            twoFactorCode = TotpHelper.GenerateCode(sharedKey)
        });
        Assert.Equal(HttpStatusCode.OK, enable.StatusCode);
        Assert.Null(RenewedHeader(enable));
    }

    [Fact]
    public async Task ManageTwoFactor_CookieClientSendingHeader_RenewsBoth()
    {
        var email = $"renew-both-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        var token = await TestHelpers.ConfirmIdentityAsync(client, new { password = TestHelpers.DefaultPassword });
        TestHelpers.SetReauthToken(client, token);

        var reset = await TestHelpers.PostWithCsrfAsync(client, "/identity/manage/2fa", new { resetSharedKey = true });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        Assert.True(SetsReAuthCookie(reset));
        var renewed = RenewedHeader(reset);
        Assert.NotNull(renewed);

        // Each renewed proof works on its own.
        using var headerOnly = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(headerOnly, email, TestHelpers.DefaultPassword);
        TestHelpers.SetReauthToken(headerOnly, renewed!);
        Assert.Equal(HttpStatusCode.OK, (await headerOnly.GetAsync("/test/reauth")).StatusCode);

        client.DefaultRequestHeaders.Remove(AuthEndpointsConstants.ReAuthHeaderName);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/test/reauth")).StatusCode);
    }

    [Fact]
    public async Task ManageTwoFactor_WithoutStampChange_ReturnsNoHeader()
    {
        var email = $"renew-nochange-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var paths = await SignInWithHeaderProofAsync(client, email, "jwt");

        // The first call creates the authenticator key; the second changes nothing.
        var setup = await client.PostAsJsonAsync(paths.TwoFactor, new { });
        Assert.Equal(HttpStatusCode.OK, setup.StatusCode);
        TestHelpers.SetReauthToken(client, RenewedHeader(setup)!);

        var unchanged = await client.PostAsJsonAsync(paths.TwoFactor, new { });
        Assert.Equal(HttpStatusCode.OK, unchanged.StatusCode);
        Assert.Null(RenewedHeader(unchanged));
    }

    [Fact]
    public async Task ManageTwoFactor_RenewedHeaderProof_KeepsOriginalExpiry()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        await using var factory = _factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(time);
            }));
        var email = $"renew-expiry-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var paths = await SignInWithHeaderProofAsync(client, email, "jwt");

        time.Advance(TimeSpan.FromMinutes(4));
        var reset = await client.PostAsJsonAsync(paths.TwoFactor, new { resetSharedKey = true });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        TestHelpers.SetReauthToken(client, RenewedHeader(reset)!);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync(paths.Info, new { })).StatusCode);

        time.Advance(TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync(paths.Info, new { })).StatusCode);
    }

    private static async Task<(string TwoFactor, string Info)> SignInWithHeaderProofAsync(
        HttpClient client,
        string email,
        string signIn)
    {
        var jwt = signIn == "jwt";
        var accessToken = jwt
            ? await TestHelpers.CreateJwtAsync(client, email, TestHelpers.DefaultPassword)
            : (await TestHelpers.LoginBearerAsync(client, email, TestHelpers.DefaultPassword)).AccessToken;
        TestHelpers.SetBearer(client, accessToken);

        var prefix = jwt ? "/identity" : "/identity/bearer";
        var confirm = await client.PostAsJsonAsync($"{prefix}/confirmIdentity", new { password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        using var doc = JsonDocument.Parse(await confirm.Content.ReadAsStringAsync());
        TestHelpers.SetReauthToken(client, TestHelpers.TryGetString(doc.RootElement, "reauthToken", "ReauthToken")!);
        return ($"{prefix}/manage/2fa", $"{prefix}/manage/info");
    }

    private static string? RenewedHeader(HttpResponseMessage response)
        => response.Headers.TryGetValues(AuthEndpointsConstants.ReAuthHeaderName, out var values) ? values.Single() : null;

    private static async Task<string> SharedKeyAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var key = TestHelpers.TryGetString(doc.RootElement, "sharedKey", "SharedKey");
        Assert.False(string.IsNullOrWhiteSpace(key));
        return key!;
    }

    private static bool SetsReAuthCookie(HttpResponseMessage response)
        => response.Headers.TryGetValues("Set-Cookie", out var values)
            && values.Any(value => value.Contains($"{AuthEndpointsConstants.ReAuthScheme}=", StringComparison.Ordinal));

    private sealed class MutableTimeProvider : TimeProvider
    {
        private DateTimeOffset _utc;

        public MutableTimeProvider(DateTimeOffset utc)
        {
            _utc = utc;
        }

        public override DateTimeOffset GetUtcNow() => _utc;

        public void Advance(TimeSpan by) => _utc = _utc.Add(by);
    }
}
