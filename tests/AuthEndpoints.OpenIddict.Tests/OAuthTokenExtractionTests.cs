using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>Where this host reads access tokens from: the Authorization header, and the query string only on listed prefixes.</summary>
public sealed class OAuthTokenExtractionTests
{
    [Fact]
    public async Task The_authorization_header_is_read_and_the_query_string_and_form_body_are_not()
    {
        await using var host = await StartWithRoutesAsync();
        var token = await IssueTokenAsync(host);
        using var api = host.Client(cookies: false);

        Assert.Equal(HttpStatusCode.OK, (await host.CallApiAsync(token)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.GetAsync($"/api/me?access_token={token}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await PostFormAsync(api, "/api/form", token)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.GetAsync($"/hubs/chat?access_token={token}")).StatusCode);
    }

    [Fact]
    public async Task A_listed_prefix_reads_the_query_token_and_other_paths_do_not()
    {
        await using var host = await StartWithRoutesAsync(options => options.QueryStringTokenPaths.Add("/hubs"));
        var token = await IssueTokenAsync(host);
        using var api = host.Client(cookies: false);

        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync($"/hubs?access_token={token}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync($"/hubs/chat?access_token={token}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync($"/hubs/chat/negotiate?access_token={token}")).StatusCode);

        // Not listed, and a look-alike that only shares the leading characters.
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.GetAsync($"/api/me?access_token={token}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.GetAsync($"/hubsevil/chat?access_token={token}")).StatusCode);

        // The form body stays off on a listed prefix too, and the header still works there.
        Assert.Equal(HttpStatusCode.Unauthorized, (await PostFormAsync(api, "/hubs/chat", token)).StatusCode);
        using var header = new HttpRequestMessage(HttpMethod.Get, "/hubs/chat");
        header.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Assert.Equal(HttpStatusCode.OK, (await api.SendAsync(header)).StatusCode);
    }

    [Fact]
    public async Task A_bad_header_token_is_not_rescued_by_a_good_query_token()
    {
        await using var host = await StartWithRoutesAsync(options => options.QueryStringTokenPaths.Add("/hubs"));
        var token = await IssueTokenAsync(host);
        using var api = host.Client(cookies: false);

        using var request = new HttpRequestMessage(HttpMethod.Get, $"/hubs/chat?access_token={token}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-token");
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task Prefixes_are_relative_to_the_path_base()
    {
        await using var host = await StartWithRoutesAsync(
            options => options.QueryStringTokenPaths.Add("/hubs"),
            services => services.AddSingleton<IStartupFilter>(new PathBaseFilter("/base")));
        var token = await IssueTokenAsync(host);
        using var api = host.Client(cookies: false);

        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync($"/base/hubs/chat?access_token={token}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.GetAsync($"/base/api/me?access_token={token}")).StatusCode);
    }

    [Theory]
    [InlineData("hubs")]
    [InlineData("")]
    [InlineData("/")]
    [InlineData("//hubs")]
    [InlineData("/hubs/")]
    [InlineData("/hubs?x=1")]
    [InlineData("/hubs#x")]
    [InlineData("https://example.com/hubs")]
    public void Query_string_token_paths_must_be_rooted_path_prefixes(string path)
    {
        var options = OAuthOptionsTests.Valid();
        options.QueryStringTokenPaths.Add(path);
        var failures = string.Join('\n', new OAuthServerOptionsValidator().Validate(null, options).Failures ?? []);
        Assert.Contains("QueryStringTokenPaths entry", failures, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/hubs")]
    [InlineData("/realtime/ws")]
    public void Rooted_query_string_token_paths_are_accepted(string path)
    {
        var options = OAuthOptionsTests.Valid();
        options.QueryStringTokenPaths.Add(path);
        Assert.True(new OAuthServerOptionsValidator().Validate(null, options).Succeeded);
    }

    private static Task<OAuthTestHost> StartWithRoutesAsync(
        Action<OAuthServerOptions>? configure = null,
        Action<IServiceCollection>? services = null)
        => StartAsync(configure, services, map: app =>
        {
            IResult Ok(HttpContext http) => Results.Ok(new { path = http.Request.Path.Value });
            app.MapGet("/hubs", Ok).RequireAuthorization("api");
            app.MapGet("/hubs/chat", Ok).RequireAuthorization("api");
            app.MapPost("/hubs/chat", Ok).RequireAuthorization("api").DisableAntiforgery();
            app.MapGet("/hubs/chat/negotiate", Ok).RequireAuthorization("api");
            app.MapGet("/hubsevil/chat", Ok).RequireAuthorization("api");
            app.MapPost("/api/form", Ok).RequireAuthorization("api").DisableAntiforgery();
        });

    private static async Task<string> IssueTokenAsync(OAuthTestHost host)
    {
        var (user, _) = await host.UserAsync("extract");
        var (_, tokens) = await host.IssueAsync(user);
        return tokens.AccessToken;
    }

    private static Task<HttpResponseMessage> PostFormAsync(HttpClient api, string path, string token)
        => api.PostAsync(path, new FormUrlEncodedContent(new Dictionary<string, string> { ["access_token"] = token }));

    private sealed class PathBaseFilter(string pathBase) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.UsePathBase(pathBase);
            next(app);
        };
    }
}
