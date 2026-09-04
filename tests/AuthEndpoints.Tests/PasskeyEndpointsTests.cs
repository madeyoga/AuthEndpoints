using System.Net;
using System.Text;
using System.Text.Json;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthEndpoints.Tests;

public class PasskeyEndpointsTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public PasskeyEndpointsTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task RegisterOptions_Default_MintsGuidShapedUserId()
    {
        var email = $"passkey-guid-{Guid.NewGuid():N}@test.local";
        using var client = TestHelpers.CreateClientWithCookies(_factory);

        var csrf = await TestHelpers.GetCsrfTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/account/passkeys/register/options")
        {
            Content = JsonContent.Create(new { email })
        };
        request.Headers.Add("RequestVerificationToken", csrf);

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var userId = ReadCreationOptionsUserId(await response.Content.ReadAsStringAsync());
        Assert.True(Guid.TryParse(userId, out _), $"Expected a Guid-shaped id, got '{userId}'.");
    }

    [Fact]
    public async Task RegisterOptions_RegisteredFactory_UsesFactoryId()
    {
        const string expectedId = "factory-minted-user-id";
        using var factory = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                services.AddPasskeyUserIdFactory(() => expectedId);
            });
        });

        var email = $"passkey-factory-{Guid.NewGuid():N}@test.local";
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        var csrf = await TestHelpers.GetCsrfTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/account/passkeys/register/options")
        {
            Content = JsonContent.Create(new { email })
        };
        request.Headers.Add("RequestVerificationToken", csrf);

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var userId = ReadCreationOptionsUserId(await response.Content.ReadAsStringAsync());
        Assert.Equal(expectedId, userId);
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

    internal static string ReadCreationOptionsUserId(string optionsJson)
    {
        using var doc = JsonDocument.Parse(optionsJson);
        Assert.True(
            doc.RootElement.TryGetProperty("user", out var user)
            || doc.RootElement.TryGetProperty("User", out user),
            "Expected user in creation options JSON.");

        var id = TestHelpers.TryGetString(user, "id", "Id");
        Assert.False(string.IsNullOrWhiteSpace(id), "Expected user.id in creation options JSON.");

        if (Guid.TryParse(id, out _))
        {
            return id;
        }

        try
        {
            var bytes = WebEncoders.Base64UrlDecode(id);
            return Encoding.UTF8.GetString(bytes);
        }
        catch (FormatException)
        {
            return id;
        }
    }
}
