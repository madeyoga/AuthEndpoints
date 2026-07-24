using System.Net;
using System.Net.Http.Json;
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

        var csrf = await TestHelpers.GetCsrfTokenAsync(client);
        using var confirmRequest = new HttpRequestMessage(HttpMethod.Post, "/identity/confirmIdentity")
        {
            Content = JsonContent.Create(new { password = TestHelpers.DefaultPassword })
        };
        confirmRequest.Headers.Add("RequestVerificationToken", csrf);

        var confirmResponse = await client.SendAsync(confirmRequest);
        Assert.Equal(HttpStatusCode.OK, confirmResponse.StatusCode);

        var reauthResponse = await client.GetAsync("/test/reauth");
        Assert.Equal(HttpStatusCode.OK, reauthResponse.StatusCode);
    }
}
