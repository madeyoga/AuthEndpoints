using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>RFC 9728 path-suffixed protected resource metadata for each resource this host accepts.</summary>
public sealed class OAuthResourceMetadataTests
{
    private const string Mcp = "https://localhost/mcp";
    private const string Tools = "https://third.example/tools";
    private const string RootMetadata = Issuer + ".well-known/oauth-protected-resource";
    private const string McpMetadata = "https://localhost/.well-known/oauth-protected-resource/mcp";

    [Fact]
    public async Task An_accepted_resource_with_a_path_gets_its_own_document()
    {
        await using var host = await StartMcpAsync();
        using var anon = host.Client(cookies: false);

        var mcp = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-protected-resource/mcp");
        Assert.Equal(Mcp, mcp.GetProperty("resource").GetString());
        Assert.Equal("MCP server", mcp.GetProperty("resource_name").GetString());
        Assert.Equal(["profile"], Strings(mcp, "scopes_supported"));
        Assert.Equal([Issuer], Strings(mcp, "authorization_servers"));
        Assert.Equal(["header"], Strings(mcp, "bearer_methods_supported"));

        // The root document still describes Audience.
        var root = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-protected-resource");
        Assert.Equal(Audience, root.GetProperty("resource").GetString());
        Assert.Equal("Test API", root.GetProperty("resource_name").GetString());
        Assert.Contains("api", Strings(root, "scopes_supported"));
        Assert.Contains("profile", Strings(root, "scopes_supported"));
    }

    [Fact]
    public async Task Audience_with_a_path_is_also_served_at_its_suffixed_path()
    {
        await using var host = await StartMcpAsync();
        using var anon = host.Client(cookies: false);

        var api = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-protected-resource/api");
        Assert.Equal(Audience, api.GetProperty("resource").GetString());
        Assert.Equal("Test API", api.GetProperty("resource_name").GetString());
    }

    [Fact]
    public async Task An_accepted_resource_without_an_entry_gets_every_scope_and_no_name()
    {
        await using var host = await StartMcpAsync(describe: false);
        using var anon = host.Client(cookies: false);

        var mcp = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-protected-resource/mcp");
        Assert.Equal(Mcp, mcp.GetProperty("resource").GetString());
        Assert.False(mcp.TryGetProperty("resource_name", out _));
        Assert.Contains("api", Strings(mcp, "scopes_supported"));
        Assert.Contains("offline_access", Strings(mcp, "scopes_supported"));
    }

    [Fact]
    public async Task Each_challenge_path_points_at_its_resource()
    {
        await using var host = await StartMcpAsync();
        using var anon = host.Client(cookies: false);

        Assert.Equal(McpMetadata, await ChallengeAsync(anon, "/mcp"));
        Assert.Equal(McpMetadata, await ChallengeAsync(anon, "/mcp/tools"));
        Assert.Equal(RootMetadata, await ChallengeAsync(anon, "/api/me"));
        Assert.Null(await ChallengeAsync(anon, "/oauth/requests/" + Guid.NewGuid()));
    }

    [Fact]
    public async Task Without_top_level_paths_every_other_path_points_at_the_root_document()
    {
        await using var host = await StartMcpAsync(configure: options => options.ProtectedResource.ChallengePaths.Clear());
        using var anon = host.Client(cookies: false);

        Assert.Equal(McpMetadata, await ChallengeAsync(anon, "/mcp"));
        Assert.Equal(RootMetadata, await ChallengeAsync(anon, "/api/me"));
        Assert.Equal(RootMetadata, await ChallengeAsync(anon, "/oauth/requests/" + Guid.NewGuid()));
    }

    [Fact]
    public async Task Resources_this_host_does_not_accept_get_no_document()
    {
        await using var host = await StartMcpAsync(configure: options => options.AdditionalResources.Add(Tools));
        using var anon = host.Client(cookies: false);

        Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync(".well-known/oauth-protected-resource/tools")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync(".well-known/oauth-protected-resource/unknown")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync(".well-known/oauth-protected-resource/mcp/extra")).StatusCode);
    }

    [Fact]
    public async Task Documents_ignore_the_host_header()
    {
        await using var host = await StartMcpAsync();
        using var anon = host.Client(cookies: false);
        using var request = new HttpRequestMessage(HttpMethod.Get, ".well-known/oauth-protected-resource/mcp");
        request.Headers.Host = "evil.example";
        var response = await anon.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain("evil.example", text, StringComparison.Ordinal);

        using var challenge = new HttpRequestMessage(HttpMethod.Get, "/mcp");
        challenge.Headers.Host = "evil.example";
        var unauthorized = await anon.SendAsync(challenge);
        Assert.Contains($"resource_metadata=\"{McpMetadata}\"", unauthorized.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Top_level_scopes_set_the_audience_documents()
    {
        await using var host = await StartMcpAsync(configure: options => options.ProtectedResource.Scopes.Add("api"));
        using var anon = host.Client(cookies: false);

        Assert.Equal(["api"], Strings(await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-protected-resource"), "scopes_supported"));
        Assert.Equal(["api"], Strings(await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-protected-resource/api"), "scopes_supported"));
    }

    [Fact]
    public async Task Accepted_resources_that_share_a_path_get_no_suffixed_document()
    {
        // Audience is https://localhost/api and OtherResource is https://other.example/api. Without the Host header
        // the two cannot be told apart, so neither is served at /api. The root document is unchanged.
        await using var host = await StartAsync(options => options.AcceptedAudiences.Add(OtherResource));
        using var anon = host.Client(cookies: false);

        Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync(".well-known/oauth-protected-resource/api")).StatusCode);
        var root = await anon.GetFromJsonAsync<JsonElement>(".well-known/oauth-protected-resource");
        Assert.Equal(Audience, root.GetProperty("resource").GetString());
        Assert.Equal(RootMetadata, await ChallengeAsync(anon, "/api/me"));
    }

    [Fact]
    public async Task Under_a_path_base_the_challenge_url_reaches_the_document()
    {
        const string AppIssuer = "https://localhost/app/";
        const string AppMcp = "https://localhost/app/mcp";
        const string AppMcpMetadata = "https://localhost/.well-known/oauth-protected-resource/app/mcp";
        await using var host = await StartAsync(
            options =>
            {
                options.Issuer = new Uri(AppIssuer);
                options.Audience = "https://localhost/app/api";
                options.AdditionalResources.Add(AppMcp);
                options.AcceptedAudiences.Add(AppMcp);
                options.ProtectedResource.Resources.Add(new OAuthProtectedResourceDefinition
                {
                    Resource = AppMcp,
                    ResourceName = "MCP server",
                    ChallengePaths = { "/mcp" },
                });
            },
            map: app => app.MapGet("/mcp", () => Results.Ok()).RequireAuthorization("api"),
            pathBase: "/app");
        using var anon = host.Client(cookies: false);

        // The 401 on the app's /mcp points at the RFC 9728 location, outside /app.
        Assert.Equal(AppMcpMetadata, await ChallengeAsync(anon, "/app/mcp"));

        // A reverse proxy that routes /.well-known/oauth-protected-resource/app/... to the app unchanged reaches it.
        var proxied = await anon.GetFromJsonAsync<JsonElement>(new Uri(AppMcpMetadata).PathAndQuery);
        Assert.Equal(AppMcp, proxied.GetProperty("resource").GetString());
        Assert.Equal("MCP server", proxied.GetProperty("resource_name").GetString());
        Assert.Equal([AppIssuer], Strings(proxied, "authorization_servers"));

        // So does a request under the PathBase, which arrives with the PathBase stripped from Request.Path.
        var direct = await anon.GetFromJsonAsync<JsonElement>("/app/.well-known/oauth-protected-resource/mcp");
        Assert.Equal(AppMcp, direct.GetProperty("resource").GetString());

        // The audience is under /app too.
        var api = await anon.GetFromJsonAsync<JsonElement>("/app/.well-known/oauth-protected-resource/api");
        Assert.Equal("https://localhost/app/api", api.GetProperty("resource").GetString());

        // The PathBase is not part of the app-relative location.
        Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync("/app/.well-known/oauth-protected-resource/app/mcp")).StatusCode);
    }

    [Fact]
    public void A_resource_outside_the_issuer_path_is_reported()
    {
        var options = Valid();
        options.Issuer = new Uri("https://localhost/app/");
        options.AdditionalResources.Add("https://elsewhere.example/tools");
        options.AcceptedAudiences.Add("https://elsewhere.example/tools");

        // Audience https://localhost/api and https://localhost/mcp are outside /app on the issuer's host. Another host is not this app's concern.
        Assert.Equal(
            ["https://localhost/api", Mcp],
            OAuthProtectedResources.OutsideIssuerPath(options).Order(StringComparer.Ordinal).ToArray());

        options.Issuer = new Uri(Issuer);
        Assert.Empty(OAuthProtectedResources.OutsideIssuerPath(options));
    }

    [Theory]
    [InlineData("not-accepted", "is not in AcceptedAudiences")]
    [InlineData("audience", "is Audience")]
    [InlineData("no-path", "needs a path and no query")]
    [InlineData("query", "needs a path and no query")]
    [InlineData("shared-path", "has the same path as another accepted resource")]
    [InlineData("unknown-scope", "scope 'nope' is not in OAuthServerOptions.Scopes")]
    [InlineData("bad-challenge-path", "challenge path 'mcp' must start with '/'")]
    [InlineData("duplicate-challenge-path", "Challenge path '/api' is listed more than once")]
    [InlineData("twice", "lists 'https://localhost/mcp' twice")]
    [InlineData("no-resource", "needs a Resource")]
    [InlineData("top-level-scope", "ProtectedResource.Scopes entry 'nope'")]
    public void Invalid_resource_settings_stop_startup(string @case, string message)
    {
        var options = Valid();
        var definition = new OAuthProtectedResourceDefinition { Resource = Mcp };
        options.ProtectedResource.Resources.Add(definition);
        switch (@case)
        {
            case "not-accepted":
                options.AcceptedAudiences.Remove(Mcp);
                break;
            case "audience":
                definition.Resource = Audience;
                break;
            case "no-path":
                options.AdditionalResources.Add("https://mcp.example/");
                options.AcceptedAudiences.Add("https://mcp.example/");
                definition.Resource = "https://mcp.example/";
                break;
            case "query":
                options.AdditionalResources.Add("https://localhost/q?x=1");
                options.AcceptedAudiences.Add("https://localhost/q?x=1");
                definition.Resource = "https://localhost/q?x=1";
                break;
            case "shared-path":
                options.AdditionalResources.Add("https://mirror.example/mcp");
                options.AcceptedAudiences.Add("https://mirror.example/mcp");
                break;
            case "unknown-scope":
                definition.Scopes.Add("nope");
                break;
            case "bad-challenge-path":
                definition.ChallengePaths.Add("mcp");
                break;
            case "duplicate-challenge-path":
                definition.ChallengePaths.Add("/api");
                break;
            case "twice":
                options.ProtectedResource.Resources.Add(new OAuthProtectedResourceDefinition { Resource = Mcp });
                break;
            case "no-resource":
                definition.Resource = null;
                break;
            case "top-level-scope":
                options.ProtectedResource.Scopes.Add("nope");
                break;
        }

        var result = new OAuthServerOptionsValidator().Validate(null, options);
        Assert.True(result.Failed);
        Assert.Contains(message, string.Join('\n', result.Failures!), StringComparison.Ordinal);
    }

    [Fact]
    public void Valid_resource_settings_pass()
    {
        var options = Valid();
        options.ProtectedResource.Resources.Add(new OAuthProtectedResourceDefinition
        {
            Resource = Mcp,
            ResourceName = "MCP server",
            Scopes = { "api" },
            ChallengePaths = { "/mcp" },
        });
        Assert.True(new OAuthServerOptionsValidator().Validate(null, options).Succeeded);
    }

    [Fact]
    public void Resource_settings_are_not_checked_while_metadata_is_off()
    {
        var options = Valid();
        options.ProtectedResource.Enabled = false;
        options.ProtectedResource.Resources.Add(new OAuthProtectedResourceDefinition { Resource = "https://unknown.example/x" });
        Assert.True(new OAuthServerOptionsValidator().Validate(null, options).Succeeded);
    }

    private static Task<OAuthTestHost> StartMcpAsync(bool describe = true, Action<OAuthServerOptions>? configure = null) => StartAsync(
        options =>
        {
            options.AdditionalResources.Add(Mcp);
            options.AcceptedAudiences.Add(Mcp);
            if (describe)
            {
                options.ProtectedResource.Resources.Add(new OAuthProtectedResourceDefinition
                {
                    Resource = Mcp,
                    ResourceName = "MCP server",
                    Scopes = { "profile" },
                    ChallengePaths = { "/mcp" },
                });
            }

            configure?.Invoke(options);
        },
        map: app =>
        {
            app.MapGet("/mcp", () => Results.Ok()).RequireAuthorization("api");
            app.MapGet("/mcp/tools", () => Results.Ok()).RequireAuthorization("api");
        });

    /// <summary>The <c>resource_metadata</c> URL of the 401 on <paramref name="path"/>, or <see langword="null"/>.</summary>
    private static async Task<string?> ChallengeAsync(HttpClient anon, string path)
    {
        var response = await anon.GetAsync(path);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var header = response.Headers.WwwAuthenticate.ToString();
        const string Marker = "resource_metadata=\"";
        var start = header.IndexOf(Marker, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        start += Marker.Length;
        return header[start..header.IndexOf('"', start)];
    }

    private static OAuthServerOptions Valid()
    {
        var options = new OAuthServerOptions
        {
            Issuer = new Uri(Issuer),
            Audience = Audience,
            LoginUrl = LoginUrl,
            ConsentUrl = ConsentUrl,
        };
        options.Scopes.Add("api");
        options.AdditionalResources.Add(Mcp);
        options.AcceptedAudiences.Add(Mcp);
        options.Certificates.UseEphemeralKeys = true;
        options.ProtectedResource.Enabled = true;
        options.ProtectedResource.ChallengePaths.Add("/api");
        return options;
    }

    private static string[] Strings(JsonElement element, string name)
        => element.GetProperty(name).EnumerateArray().Select(item => item.GetString()!).ToArray();
}
