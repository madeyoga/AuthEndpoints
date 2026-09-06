using System.Net;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Tests;

public class IdentityAccountEndpointsTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public IdentityAccountEndpointsTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Register_SendsConfirmationEmail()
    {
        var email = $"register-mail-{Guid.NewGuid():N}@test.local";
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.PostAsJsonAsync("/identity/register", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var mailbox = _factory.Services.GetRequiredService<CapturingEmailSender>();
        var mail = Assert.Single(mailbox.Snapshot(), item => item.Email == email && item.Kind == "confirm");
        Assert.Contains("/identity/confirmEmail", mail.Body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ConfirmEmail_ValidCode_Succeeds()
    {
        var email = $"confirm-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email, emailConfirmed: false);
        var code = await TestHelpers.GenerateEmailConfirmationCodeAsync(_factory, user);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.GetAsync($"/identity/confirmEmail?userId={Uri.EscapeDataString(user.Id)}&code={Uri.EscapeDataString(code)}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("confirming", body, StringComparison.OrdinalIgnoreCase);

        var confirmed = await TestHelpers.FindUserByEmailAsync(_factory, email);
        Assert.NotNull(confirmed);
        Assert.True(confirmed.EmailConfirmed);
    }

    [Fact]
    public async Task ConfirmEmail_BadCode_ReturnsUnauthorized()
    {
        var email = $"confirm-bad-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email, emailConfirmed: false);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.GetAsync($"/identity/confirmEmail?userId={Uri.EscapeDataString(user.Id)}&code=not-a-valid-code");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ConfirmEmail_UnknownUser_ReturnsUnauthorized()
    {
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.GetAsync($"/identity/confirmEmail?userId={Guid.NewGuid():N}&code=abc");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ResendConfirmationEmail_Authenticated_AlwaysReturnsOk()
    {
        var email = $"resend-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email, emailConfirmed: false);
        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var existing = await TestHelpers.PostWithCsrfAsync(
            client,
            "/identity/resendConfirmationEmail",
            new { email });
        Assert.Equal(HttpStatusCode.OK, existing.StatusCode);

        var unknown = await TestHelpers.PostWithCsrfAsync(
            client,
            "/identity/resendConfirmationEmail",
            new { email = $"missing-{Guid.NewGuid():N}@test.local" });
        Assert.Equal(HttpStatusCode.OK, unknown.StatusCode);
    }

    [Fact]
    public async Task ForgotPassword_AlwaysReturnsOk()
    {
        var email = $"forgot-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var known = await client.PostAsJsonAsync("/identity/forgotPassword", new { email });
        Assert.Equal(HttpStatusCode.OK, known.StatusCode);

        var unknown = await client.PostAsJsonAsync(
            "/identity/forgotPassword",
            new { email = $"missing-{Guid.NewGuid():N}@test.local" });
        Assert.Equal(HttpStatusCode.OK, unknown.StatusCode);
    }

    [Fact]
    public async Task ResetPassword_ValidCode_AllowsLoginWithNewPassword()
    {
        var email = $"reset-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email);
        var resetCode = await TestHelpers.GeneratePasswordResetCodeAsync(_factory, user);
        const string newPassword = "NewPassw0rd!";
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var reset = await client.PostAsJsonAsync("/identity/resetPassword", new
        {
            email,
            resetCode,
            newPassword
        });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);

        var loginOld = await client.PostAsJsonAsync("/identity/login", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.Unauthorized, loginOld.StatusCode);

        await TestHelpers.LoginCookieAsync(client, email, newPassword);
    }

    [Fact]
    public async Task ResetPassword_UnknownUser_ReturnsValidationProblem()
    {
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var response = await client.PostAsJsonAsync("/identity/resetPassword", new
        {
            email = $"missing-{Guid.NewGuid():N}@test.local",
            resetCode = "invalid",
            newPassword = "NewPassw0rd!"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("InvalidToken", body, StringComparison.OrdinalIgnoreCase);
    }
}
