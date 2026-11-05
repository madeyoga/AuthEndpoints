using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

public sealed class OAuthMetadataTests
{
    [Fact]
    public async Task Server_metadata_uses_the_configured_issuer_not_the_host_header()
    {
        await using var host = await StartAsync();
        using var anon = host.Client(cookies: false);
        using var request = new HttpRequestMessage(HttpMethod.Get, ".well-known/oauth-authorization-server");
        request.Headers.Host = "evil.example";

        var response = await anon.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, text);
        var server = JsonSerializer.Deserialize<JsonElement>(text);

        Assert.True(!text.Contains("evil.example", StringComparison.Ordinal), text);
        Assert.Equal(Issuer, server.GetProperty("issuer").GetString());
        Assert.Equal(Issuer + "connect/authorize", server.GetProperty("authorization_endpoint").GetString());
        Assert.Equal(Issuer + "connect/token", server.GetProperty("token_endpoint").GetString());
        Assert.Equal(Issuer + "connect/revoke", server.GetProperty("revocation_endpoint").GetString());
        Assert.Equal(Issuer + "connect/register", server.GetProperty("registration_endpoint").GetString());
        Assert.Equal(["S256"], Strings(server, "code_challenge_methods_supported"));
        Assert.Contains("none", Strings(server, "token_endpoint_auth_methods_supported"));
        Assert.Equal(["code"], Strings(server, "response_types_supported"));
        Assert.Contains("authorization_code", Strings(server, "grant_types_supported"));
        Assert.Contains("refresh_token", Strings(server, "grant_types_supported"));
        Assert.DoesNotContain("implicit", Strings(server, "grant_types_supported"));
        Assert.Contains("api", Strings(server, "scopes_supported"));
        Assert.True(server.GetProperty("authorization_response_iss_parameter_supported").GetBoolean());
    }

    [Fact]
    public async Task Protected_resource_metadata_and_the_challenge_point_at_the_server()
    {
        await using var host = await StartAsync();
        using var anon = host.Client(cookies: false);

        var resource = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-protected-resource");
        Assert.Equal(Audience, resource.GetProperty("resource").GetString());
        Assert.Equal(Issuer, resource.GetProperty("authorization_servers")[0].GetString());
        Assert.Equal("header", resource.GetProperty("bearer_methods_supported")[0].GetString());
        Assert.Equal("Test API", resource.GetProperty("resource_name").GetString());

        var api = await anon.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, api.StatusCode);
        var challenge = api.Headers.WwwAuthenticate.Single();
        Assert.Equal("Bearer", challenge.Scheme);
        Assert.Contains($"resource_metadata=\"{Issuer}.well-known/oauth-protected-resource\"", challenge.Parameter, StringComparison.Ordinal);

        var outside = await anon.GetAsync("/oauth/requests/" + Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Unauthorized, outside.StatusCode);
        Assert.DoesNotContain("resource_metadata", outside.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Protected_resource_metadata_is_off_by_default()
    {
        await using var host = await StartAsync(options => options.ProtectedResource.Enabled = false);
        using var anon = host.Client(cookies: false);

        Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync(".well-known/oauth-protected-resource")).StatusCode);
        var api = await anon.GetAsync("/api/me");
        Assert.DoesNotContain("resource_metadata", api.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("", "Bearer resource_metadata=\"m\"")]
    [InlineData("Bearer", "Bearer resource_metadata=\"m\"")]
    [InlineData("Bearer error=\"invalid_token\"", "Bearer error=\"invalid_token\", resource_metadata=\"m\"")]
    [InlineData("Cookie", "Cookie, Bearer resource_metadata=\"m\"")]
    [InlineData("Bearer resource_metadata=\"x\"", "Bearer resource_metadata=\"x\"")]
    public void Challenge_header_keeps_existing_parameters(string existing, string expected)
        => Assert.Equal(expected, OAuthServerApplicationBuilderExtensions.WithResourceMetadata(existing, "resource_metadata=\"m\""));

    private static string[] Strings(JsonElement element, string name)
        => element.GetProperty(name).EnumerateArray().Select(item => item.GetString()!).ToArray();
}
