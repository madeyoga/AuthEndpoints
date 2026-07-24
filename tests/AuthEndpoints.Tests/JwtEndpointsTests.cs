using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints.Jwt;

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
        var response = await client.PostAsJsonAsync("/auth/create", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(
            doc.RootElement.TryGetProperty("accessToken", out var token)
            || doc.RootElement.TryGetProperty("AccessToken", out token));
        Assert.False(string.IsNullOrWhiteSpace(token.GetString()));
    }

    [Fact]
    public async Task Create_WithTwoFactorEnabledAndNoCode_ReturnsRequiresTwoFactor()
    {
        var email = $"jwt2fa-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email, twoFactorEnabled: true);

        using var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/auth/create", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("requiresTwoFactor", body, StringComparison.OrdinalIgnoreCase);
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
}
