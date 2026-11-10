using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests;

public class AntiforgeryBearerSchemesTests : IClassFixture<TestWebApplicationFactory>
{
    private const string HeaderScheme = "TestHeaderScheme";
    private const string ValidToken = "custom-token-ok";
    private const string ValidApiKey = "custom-api-key-ok";

    private readonly TestWebApplicationFactory _factory;

    public AntiforgeryBearerSchemesTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public void Defaults_AreIdentityBearerAndJwt()
    {
        string[] expected = [IdentityConstants.BearerScheme, JwtBearerDefaults.AuthenticationScheme];
        Assert.Equal(expected, new AuthEndpointsAntiforgeryOptions().BearerSchemes);

        var resolved = _factory.Services.GetRequiredService<IOptions<AuthEndpointsAntiforgeryOptions>>().Value;
        Assert.Equal(expected, resolved.BearerSchemes);
    }

    [Fact]
    public async Task CustomHeaderScheme_NotInList_RequiresToken()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = WithHeaderScheme(root, addToList: false);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ValidToken);

        var response = await client.PostAsync("/test/csrf", content: null);
        await AssertCsrfRejectedAsync(response);
    }

    [Fact]
    public async Task CustomHeaderScheme_InList_SkipsCheck()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = WithHeaderScheme(root, addToList: true);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ValidToken);

        var response = await client.PostAsync("/test/csrf", content: null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CustomHeaderScheme_InList_InvalidToken_RequiresToken()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = WithHeaderScheme(root, addToList: true);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "wrong");

        var response = await client.PostAsync("/test/csrf", content: null);
        await AssertCsrfRejectedAsync(response);
    }

    [Fact]
    public async Task CustomScheme_ApiKeyHeaderWithoutAuthorizationBearer_RequiresToken()
    {
        // The skip needs Authorization: Bearer; another header alone does not skip the check.
        await using var root = new TestWebApplicationFactory();
        using var factory = WithHeaderScheme(root, addToList: true);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", ValidApiKey);

        var response = await client.PostAsync("/test/csrf", content: null);
        await AssertCsrfRejectedAsync(response);
    }

    [Fact]
    public async Task CookieSession_PlusCustomBearerHeader_RequiresToken()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = WithHeaderScheme(root, addToList: true);
        var email = $"csrf-custom-cookie-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);

        using var client = TestHelpers.CreateClientWithCookies(factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ValidToken);

        var response = await client.PostAsync("/test/csrf", content: null);
        await AssertCsrfRejectedAsync(response);
    }

    [Fact]
    public async Task CookieHandlerSchemeInList_IsIgnored()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = root.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.Configure<AuthEndpointsAntiforgeryOptions>(o => o.BearerSchemes.Add(IdentityConstants.ExternalScheme))));

        using var client = TestHelpers.CreateClientWithCookies(factory);
        var signIn = await client.PostAsJsonAsync(
            "/test/external-cookie",
            new { provider = "Test", key = Guid.NewGuid().ToString("N") });
        Assert.Equal(HttpStatusCode.NoContent, signIn.StatusCode);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "anything");

        var response = await client.PostAsync("/test/csrf", content: null);
        await AssertCsrfRejectedAsync(response);
    }

    [Fact]
    public async Task EmptyList_JwtBearer_RequiresToken()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = root.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.Configure<AuthEndpointsAntiforgeryOptions>(o => o.BearerSchemes.Clear())));
        var email = $"csrf-empty-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);

        using var client = factory.CreateClient();
        TestHelpers.SetBearer(client, await TestHelpers.CreateJwtAsync(client, email, TestHelpers.DefaultPassword));

        var response = await client.PostAsync("/test/csrf-auth", content: null);
        await AssertCsrfRejectedAsync(response);
    }

    [Theory]
    [InlineData("jwt", "/test/csrf-auth-strict")]
    [InlineData("identity-bearer", "/test/csrf-auth-strict")]
    [InlineData("jwt", "/test/csrf-strict-group/")]
    [InlineData("identity-bearer", "/test/csrf-strict-group/")]
    public async Task AllowBearerFalse_ValidBearer_RequiresToken(string source, string path)
    {
        var email = $"csrf-strict-{source}-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = _factory.CreateClient();
        var token = source == "jwt"
            ? await TestHelpers.CreateJwtAsync(client, email, TestHelpers.DefaultPassword)
            : (await TestHelpers.LoginBearerAsync(client, email, TestHelpers.DefaultPassword)).AccessToken;
        TestHelpers.SetBearer(client, token);

        // The same bearer skips the check on a default RequireAntiforgery() route.
        var lenient = await client.PostAsync("/test/csrf-auth", content: null);
        Assert.Equal(HttpStatusCode.OK, lenient.StatusCode);

        var strict = await client.PostAsync(path, content: null);
        await AssertCsrfRejectedAsync(strict);
    }

    // The metadata records which mode a route was mapped with, so a route's strictness can be read without calling it.
    [Theory]
    [InlineData("/test/csrf-auth", true)]
    [InlineData("/test/csrf-auth-strict", false)]
    [InlineData("/test/csrf-strict-group/", false)]
    public void RouteMetadata_RecordsAllowBearer(string path, bool allowBearer)
    {
        using var client = _factory.CreateClient();
        var endpoint = _factory.Services.GetServices<EndpointDataSource>()
            .SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>()
            .Single(route => route.RoutePattern.RawText == path);

        var metadata = endpoint.Metadata.GetMetadata<AuthEndpointsAntiforgeryMetadata>();
        Assert.NotNull(metadata);
        Assert.Equal(allowBearer, metadata.AllowBearer);
    }

    [Theory]
    [InlineData("/test/csrf-auth-strict")]
    [InlineData("/test/csrf-strict-group/")]
    public async Task AllowBearerFalse_CookieWithToken_Succeeds(string path)
    {
        var email = $"csrf-strict-cookie-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(_factory, email);

        using var client = TestHelpers.CreateClientWithCookies(_factory);
        await TestHelpers.LoginCookieAsync(client, email, TestHelpers.DefaultPassword);

        var without = await client.PostAsync(path, content: null);
        await AssertCsrfRejectedAsync(without);

        var with = await TestHelpers.PostWithCsrfAsync(client, path, body: null);
        Assert.Equal(HttpStatusCode.OK, with.StatusCode);
    }

    [Fact]
    public async Task ReAuth_CustomSchemeInList_ConfirmIdentityReturnsTokenWithoutCookie()
    {
        // The list replaces the defaults: only the custom scheme (which accepts any bearer value) skips.
        await using var root = new TestWebApplicationFactory();
        using var factory = WithHeaderScheme(root, addToList: true, acceptAnyBearer: true, replaceDefaults: true);
        var email = $"reauth-custom-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        TestHelpers.SetBearer(client, await TestHelpers.CreateJwtAsync(client, email, TestHelpers.DefaultPassword));

        var confirm = await client.PostAsJsonAsync(
            "/identity/confirmIdentity",
            new { password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        Assert.False(SetsReAuthCookie(confirm));
    }

    [Fact]
    public async Task ReAuth_EmptyList_ConfirmIdentityRequiresTokenAndSetsCookie()
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = root.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.Configure<AuthEndpointsAntiforgeryOptions>(o => o.BearerSchemes.Clear());
            // Bind the CSRF token to the JWT user, the scheme the confirm route authenticates with.
            services.PostConfigure<AuthenticationOptions>(o =>
                o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme);
        }));
        var email = $"reauth-empty-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);

        using var client = TestHelpers.CreateClientWithCookies(factory);
        TestHelpers.SetBearer(client, await TestHelpers.CreateJwtAsync(client, email, TestHelpers.DefaultPassword));

        var without = await client.PostAsJsonAsync(
            "/identity/confirmIdentity",
            new { password = TestHelpers.DefaultPassword });
        await AssertCsrfRejectedAsync(without);

        var with = await TestHelpers.PostWithCsrfAsync(
            client,
            "/identity/confirmIdentity",
            new { password = TestHelpers.DefaultPassword },
            csrfPath: "/test/csrfToken");
        Assert.Equal(HttpStatusCode.OK, with.StatusCode);
        Assert.True(SetsReAuthCookie(with));
    }

    private static WebApplicationFactory<Program> WithHeaderScheme(
        TestWebApplicationFactory root,
        bool addToList,
        bool acceptAnyBearer = false,
        bool replaceDefaults = false) =>
        root.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.AddAuthentication()
                .AddScheme<TestHeaderSchemeOptions, TestHeaderHandler>(HeaderScheme, o => o.AcceptAnyBearer = acceptAnyBearer);
            if (addToList)
            {
                services.Configure<AuthEndpointsAntiforgeryOptions>(o =>
                {
                    if (replaceDefaults)
                    {
                        o.BearerSchemes.Clear();
                    }

                    o.BearerSchemes.Add(HeaderScheme);
                });
            }
        }));

    private static async Task AssertCsrfRejectedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("CSRF", await response.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
    }

    private static bool SetsReAuthCookie(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values)
        && values.Any(value => value.Contains($"{AuthEndpointsConstants.ReAuthScheme}=", StringComparison.Ordinal));

    private sealed class TestHeaderSchemeOptions : AuthenticationSchemeOptions
    {
        public bool AcceptAnyBearer { get; set; }
    }

    // Reads Authorization: Bearer <token>, or an X-Api-Key header.
    private sealed class TestHeaderHandler(
        IOptionsMonitor<TestHeaderSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder) : AuthenticationHandler<TestHeaderSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var authorization = Request.Headers.Authorization.ToString();
            var bearer = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? authorization["Bearer ".Length..].Trim()
                : null;
            var apiKey = Request.Headers["X-Api-Key"].ToString();

            var ok = (!string.IsNullOrEmpty(bearer) && (Options.AcceptAnyBearer || bearer == ValidToken))
                || apiKey == ValidApiKey;
            if (!ok)
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "custom")], Scheme.Name);
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
        }
    }
}
