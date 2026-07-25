using System.Net;
using System.Text.Json;

namespace AuthEndpoints.Tests;

public class PasskeyEndpointsTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public PasskeyEndpointsTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task RegisterOptions_ExistingEmail_ReturnsOptionsJson()
    {
        var email = $"passkey-enum-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var csrf = await TestHelpers.GetCsrfTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/account/passkeys/register/options")
        {
            Content = JsonContent.Create(new { email })
        };
        request.Headers.Add("RequestVerificationToken", csrf);

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("already exists", body, StringComparison.OrdinalIgnoreCase);
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
    }

    [Fact]
    public async Task Register_ExistingEmail_ReturnsGenericBadRequest()
    {
        var email = $"passkey-reg-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var csrf = await TestHelpers.GetCsrfTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/account/passkeys/register")
        {
            Content = JsonContent.Create(new
            {
                email,
                credentialJson = "{}"
            })
        };
        request.Headers.Add("RequestVerificationToken", csrf);

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Unable to complete registration", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("already exists", body, StringComparison.OrdinalIgnoreCase);
    }
}
