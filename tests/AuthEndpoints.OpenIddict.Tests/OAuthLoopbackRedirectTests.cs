using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using Microsoft.Extensions.Options;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>RFC 8252 §7.3: loopback IP redirect URIs accept any port.</summary>
public sealed class OAuthLoopbackRedirectTests
{
    [Theory]
    [InlineData("http://127.0.0.1:9/callback", "http://127.0.0.1:51234/callback")]
    [InlineData("http://127.0.0.1/callback", "http://127.0.0.1:51234/callback")]
    [InlineData("http://127.0.0.1:9/callback", "http://127.0.0.1/callback")]
    [InlineData("http://[::1]:9/callback", "http://[::1]:51234/callback")]
    [InlineData("http://127.0.0.1:9/callback?x=1", "http://127.0.0.1:51234/callback?x=1")]
    public async Task A_loopback_ip_redirect_may_use_any_port_through_the_whole_flow(string registered, string requested)
    {
        await using var host = await StartAsync();
        var client = await host.RegisterAsync(redirect: registered);
        var (user, userId) = await host.UserAsync("loopback");
        var pkce = Pkce.Create();

        var id = await OAuthTestHost.StartAsync(user, client.ClientId, requested, pkce.Challenge);
        var card = await user.GetFromJsonAsync<JsonElement>($"/oauth/requests/{id}");
        Assert.Equal(new Uri(requested).Authority, card.GetProperty("redirectHost").GetString());
        var response = await PostConsentAsync(user, id, "approve");
        var redirect = (await response.Content.ReadFromJsonAsync<OAuthConsentRedirect>())!.RedirectUrl;
        Assert.StartsWith(requested.Split('?')[0], redirect, StringComparison.Ordinal);
        var code = Query(redirect)["code"];

        using var anon = host.Client(cookies: false);
        // The token request must repeat the redirect URI used at authorize, port included.
        Assert.Equal("invalid_grant", await ErrorAsync(await TokenAsync(anon, CodeGrant(client.ClientId, registered, code, pkce.Verifier))));
        var replay = await StartAndApproveAsync(user, client.ClientId, requested, pkce);
        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client.ClientId, requested, replay, pkce.Verifier)));
        Assert.Equal(userId, await host.SubjectAsync(tokens.AccessToken));
    }

    [Theory]
    [InlineData("http://127.0.0.1:9/callback", "http://127.0.0.1:51234/other")]
    [InlineData("http://127.0.0.1:9/callback", "http://127.0.0.1:51234/callback?x=1")]
    [InlineData("http://127.0.0.1:9/callback", "http://127.0.0.2:51234/callback")]
    [InlineData("http://127.0.0.1:9/callback", "http://[::1]:51234/callback")]
    [InlineData("http://127.0.0.1:9/callback", "http://user@127.0.0.1:51234/callback")]
    [InlineData("http://localhost:9/callback", "http://localhost:51234/callback")]
    [InlineData("https://app.example/callback", "https://app.example:8443/callback")]
    public async Task Anything_but_the_port_must_still_match(string registered, string requested)
    {
        await using var host = await StartAsync();
        var client = await host.RegisterAsync(redirect: registered);
        var (user, _) = await host.UserAsync("strict");

        var response = await user.GetAsync(AuthorizeUrl(client.ClientId, requested, Pkce.Create().Challenge));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task Seeded_clients_and_developer_apps_get_the_same_rule()
    {
        await using var host = await StartAsync(options =>
        {
            var cli = new OAuthClientDefinition { ClientId = "seeded-cli", DisplayName = "Seeded CLI" };
            cli.RedirectUris.Add("http://127.0.0.1/callback");
            options.Clients.Add(cli);
        });
        var (user, _) = await host.UserAsync("both");
        await OAuthTestHost.StartAsync(user, "seeded-cli", "http://127.0.0.1:40001/callback", Pkce.Create().Challenge);

        var csrf = await user.GetFromJsonAsync<JsonElement>("/test/csrf");
        using var create = new HttpRequestMessage(HttpMethod.Post, "/oauth/apps")
        {
            Content = JsonContent.Create(new { name = "CLI", homepageUrl = "https://dev.example", redirectUris = new[] { "http://[::1]/callback" } }),
        };
        create.Headers.Add(CsrfHeader, csrf.GetProperty("token").GetString());
        var app = (await (await user.SendAsync(create)).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("app");
        await OAuthTestHost.StartAsync(user, app.GetProperty("clientId").GetString()!, "http://[::1]:40002/callback", Pkce.Create().Challenge);
    }

    [Fact]
    public async Task The_built_in_redirect_check_is_replaced_at_the_same_position()
    {
        await using var host = await StartAsync();
        var server = host.Services.GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;

        var builtIn = OpenIddictServerHandlers.Authentication.ValidateClientRedirectUri.Descriptor;
        Assert.DoesNotContain(server.Handlers, handler => handler.ServiceDescriptor.ServiceType == builtIn.ServiceDescriptor.ServiceType);
        var replacement = Assert.Single(server.Handlers, handler => handler.ServiceDescriptor.ServiceType == typeof(ValidateClientRedirectUriWithLoopbackPorts));
        Assert.Equal(builtIn.Order, replacement.Order);
    }

    private static async Task<string> StartAndApproveAsync(HttpClient user, string clientId, string redirect, Pkce pkce)
        => (await ApproveAsync(user, await OAuthTestHost.StartAsync(user, clientId, redirect, pkce.Challenge)))["code"];
}
