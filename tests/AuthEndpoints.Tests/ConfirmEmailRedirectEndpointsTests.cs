using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthEndpoints.Tests;

public class ConfirmEmailRedirectEndpointsTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public ConfirmEmailRedirectEndpointsTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Unset_ValidCode_ReturnsThankYou()
    {
        var email = $"confirm-unset-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email, emailConfirmed: false);
        var code = await TestHelpers.GenerateEmailConfirmationCodeAsync(_factory, user);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.GetAsync(ConfirmPath(user.Id, code));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Thank you for confirming your email.", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unset_BadCode_ReturnsUnauthorized()
    {
        var email = $"confirm-unset-bad-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email, emailConfirmed: false);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.GetAsync(ConfirmPath(user.Id, "not-a-valid-code"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task RootedPath_Success_RedirectsConfirmedConfirm()
    {
        using WebApplicationFactory<Program> factory = CreateFactory("/auth/email-confirmed");
        var email = $"confirm-root-ok-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(factory, email, emailConfirmed: false);
        var code = await TestHelpers.GenerateEmailConfirmationCodeAsync(factory, user);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var response = await client.GetAsync(ConfirmPath(user.Id, code));

        Uri location = RequireRedirectLocation(response);
        Assert.Equal("/auth/email-confirmed", location.AbsolutePath);
        AssertStatusAndFlow(location, "confirmed", "confirm");

        var confirmed = await TestHelpers.FindUserByEmailAsync(factory, email);
        Assert.NotNull(confirmed);
        Assert.True(confirmed.EmailConfirmed);
    }

    [Fact]
    public async Task RootedPath_Failure_RedirectsFailedConfirm()
    {
        using WebApplicationFactory<Program> factory = CreateFactory("/auth/email-confirmed");
        var email = $"confirm-root-fail-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(factory, email, emailConfirmed: false);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var response = await client.GetAsync(ConfirmPath(user.Id, "not-a-valid-code"));

        Uri location = RequireRedirectLocation(response);
        Assert.Equal("/auth/email-confirmed", location.AbsolutePath);
        AssertStatusAndFlow(location, "failed", "confirm");

        var unchanged = await TestHelpers.FindUserByEmailAsync(factory, email);
        Assert.NotNull(unchanged);
        Assert.False(unchanged.EmailConfirmed);
    }

    [Fact]
    public async Task AbsoluteAllowlisted_Success_RedirectsOriginStatusAndFlow()
    {
        using WebApplicationFactory<Program> factory = CreateFactory(
            "https://spa.example.com/auth/email-confirmed",
            "https://spa.example.com");
        var email = $"confirm-abs-ok-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(factory, email, emailConfirmed: false);
        var code = await TestHelpers.GenerateEmailConfirmationCodeAsync(factory, user);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var response = await client.GetAsync(ConfirmPath(user.Id, code));

        Uri location = RequireRedirectLocation(response);
        Assert.Equal("https", location.Scheme);
        Assert.Equal("spa.example.com", location.Host);
        Assert.Equal("/auth/email-confirmed", location.AbsolutePath);
        AssertStatusAndFlow(location, "confirmed", "confirm");
    }

    [Fact]
    public async Task AbsoluteNotAllowlisted_RefusesRedirect_KeepsThankYou()
    {
        using WebApplicationFactory<Program> factory = CreateFactory(
            "https://spa.example.com/auth/email-confirmed",
            "https://other.example.com");
        var email = $"confirm-abs-refuse-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(factory, email, emailConfirmed: false);
        var code = await TestHelpers.GenerateEmailConfirmationCodeAsync(factory, user);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var response = await client.GetAsync(ConfirmPath(user.Id, code));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Thank you for confirming your email.", body, StringComparison.Ordinal);

        var confirmed = await TestHelpers.FindUserByEmailAsync(factory, email);
        Assert.NotNull(confirmed);
        Assert.True(confirmed.EmailConfirmed);
    }

    [Fact]
    public async Task ChangeEmail_Success_RedirectsChangeEmailConfirmed()
    {
        using WebApplicationFactory<Program> factory = CreateFactory("/auth/email-confirmed");
        var email = $"confirm-change-{Guid.NewGuid():N}@test.local";
        var newEmail = $"confirm-changed-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(factory, email);
        var code = await TestHelpers.GenerateChangeEmailCodeAsync(factory, user, newEmail);
        using var client = TestHelpers.CreateClientWithCookies(factory);

        var response = await client.GetAsync(
            $"/identity/confirmEmail?userId={Uri.EscapeDataString(user.Id)}&code={Uri.EscapeDataString(code)}&changedEmail={Uri.EscapeDataString(newEmail)}");

        Uri location = RequireRedirectLocation(response);
        AssertStatusAndFlow(location, "confirmed", "change-email");

        var changed = await TestHelpers.FindUserByEmailAsync(factory, newEmail);
        Assert.NotNull(changed);
        Assert.Equal(newEmail, changed.Email);
        Assert.True(changed.EmailConfirmed);
    }

    private WebApplicationFactory<Program> CreateFactory(string redirectUri, string? allowedOrigins = null)
    {
        return _factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("TestDbName", "ConfirmEmailRedirect_" + Guid.NewGuid().ToString("N"));
            builder.UseSetting("AE_CONFIRM_EMAIL_REDIRECT_URI", redirectUri);
            if (allowedOrigins is not null)
            {
                builder.UseSetting("AE_CONFIRM_EMAIL_ALLOWED_ORIGINS", allowedOrigins);
            }
        });
    }

    private static string ConfirmPath(string userId, string code) =>
        $"/identity/confirmEmail?userId={Uri.EscapeDataString(userId)}&code={Uri.EscapeDataString(code)}";

    private static Uri RequireRedirectLocation(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Uri location = response.Headers.Location;
        if (!location.IsAbsoluteUri)
        {
            location = new Uri(new Uri("http://localhost"), location);
        }

        return location;
    }

    private static void AssertStatusAndFlow(Uri location, string status, string flow)
    {
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal(status, (string?)query["status"]);
        Assert.Equal(flow, (string?)query["flow"]);
        Assert.False(query.ContainsKey("userId"));
        Assert.False(query.ContainsKey("code"));
        Assert.False(query.ContainsKey("email"));
    }
}
