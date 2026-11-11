using System.Net;
using System.Net.Http.Headers;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>An OAuth access token in <c>Authorization: Bearer</c> skips the CSRF check of <c>RequireAntiforgery()</c>.</summary>
public sealed class OAuthAntiforgeryTests
{
    [Fact]
    public async Task The_validation_scheme_is_added_to_the_bearer_schemes_once()
    {
        // A host that listed the scheme itself before registering the server.
        await using var host = await StartWithRoutesAsync(beforeServer: services =>
            services.Configure<AuthEndpointsAntiforgeryOptions>(options =>
                options.BearerSchemes.Add(OAuthServerServiceCollectionExtensions.ValidationScheme)));

        var schemes = host.Services.GetRequiredService<IOptions<AuthEndpointsAntiforgeryOptions>>().Value.BearerSchemes;
        Assert.Single(schemes, OAuthServerServiceCollectionExtensions.ValidationScheme);
        Assert.Contains(Microsoft.AspNetCore.Identity.IdentityConstants.BearerScheme, schemes);
    }

    [Fact]
    public async Task An_access_token_skips_the_csrf_check_unless_the_route_disallows_bearer()
    {
        await using var host = await StartWithRoutesAsync();
        var token = await IssueTokenAsync(host);
        using var api = host.Client(cookies: false);

        Assert.Equal(HttpStatusCode.OK, (await PostAsync(api, "/api/write", token)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(api, "/api/strict", token)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync(api, "/api/write", "not-a-token")).StatusCode);
    }

    [Fact]
    public async Task A_host_can_take_the_validation_scheme_back_out()
    {
        await using var host = await StartWithRoutesAsync(services =>
            services.PostConfigure<AuthEndpointsAntiforgeryOptions>(options =>
                options.BearerSchemes.Remove(OAuthServerServiceCollectionExtensions.ValidationScheme)));
        var token = await IssueTokenAsync(host);
        using var api = host.Client(cookies: false);

        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(api, "/api/write", token)).StatusCode);
    }

    private static Task<OAuthTestHost> StartWithRoutesAsync(
        Action<IServiceCollection>? services = null, Action<IServiceCollection>? beforeServer = null)
        => StartAsync(services: services, beforeServer: beforeServer, map: app =>
        {
            app.MapPost("/api/write", () => Results.Ok()).RequireAuthorization("api").RequireAntiforgery();
            app.MapPost("/api/strict", () => Results.Ok()).RequireAuthorization("api").RequireAntiforgery(allowBearer: false);
        });

    private static async Task<string> IssueTokenAsync(OAuthTestHost host)
    {
        var (user, _) = await host.UserAsync("antiforgery");
        var (_, tokens) = await host.IssueAsync(user);
        return tokens.AccessToken;
    }

    private static Task<HttpResponseMessage> PostAsync(HttpClient api, string path, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return api.SendAsync(request);
    }
}
