using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Tests;

public class AntiforgeryCookieTokenTests
{
    private const string AccessTokenCookie = "access_token";

    public static TheoryData<string> TokenSources => new()
    {
        "jwt",
        "identity-bearer"
    };

    [Theory]
    [MemberData(nameof(TokenSources))]
    public async Task HeaderToken_SkipsCsrf(string source)
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateCookieReadingFactory(root, source);
        var token = await IssueTokenAsync(factory, source);

        using var client = factory.CreateClient();
        TestHelpers.SetBearer(client, token);
        var response = await client.PostAsync("/test/csrf-auth", content: null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(TokenSources))]
    public async Task CookieToken_RequiresCsrf(string source)
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateCookieReadingFactory(root, source);
        var token = await IssueTokenAsync(factory, source);

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            HandleCookies = false
        });

        var without = await SendAsync(client, token, includeAuthorization: false, includeCsrf: false);
        Assert.Equal(HttpStatusCode.BadRequest, without.StatusCode);
        Assert.Contains("CSRF", await without.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);

        var with = await SendAsync(client, token, includeAuthorization: false, includeCsrf: true);
        Assert.True(with.StatusCode == HttpStatusCode.OK, await with.Content.ReadAsStringAsync());
    }

    [Theory]
    [MemberData(nameof(TokenSources))]
    public async Task CookieAndHeaderTogether_RequireCsrf(string source)
    {
        await using var root = new TestWebApplicationFactory();
        using var factory = CreateCookieReadingFactory(root, source);
        var token = await IssueTokenAsync(factory, source);

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            HandleCookies = false
        });

        var without = await SendAsync(client, token, includeAuthorization: true, includeCsrf: false);
        Assert.Equal(HttpStatusCode.BadRequest, without.StatusCode);
        Assert.Contains("CSRF", await without.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);

        var with = await SendAsync(client, token, includeAuthorization: true, includeCsrf: true);
        Assert.Equal(HttpStatusCode.OK, with.StatusCode);
    }

    private static WebApplicationFactory<Program> CreateCookieReadingFactory(TestWebApplicationFactory root, string source) =>
        root.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // The CSRF token is bound to the authenticated user. Authenticate the cookie
                // token on the token request, the same way a browser would send it.
                services.PostConfigure<AuthenticationOptions>(options =>
                {
                    options.DefaultAuthenticateScheme = source == "jwt"
                        ? JwtBearerDefaults.AuthenticationScheme
                        : IdentityConstants.BearerScheme;
                });

                services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
                {
                    options.Events ??= new JwtBearerEvents();
                    options.Events.OnMessageReceived = context =>
                    {
                        if (context.Request.Cookies.TryGetValue(AccessTokenCookie, out var cookie)
                            && !string.IsNullOrEmpty(cookie))
                        {
                            context.Token = cookie;
                        }

                        return Task.CompletedTask;
                    };
                });

                services.PostConfigure<BearerTokenOptions>(IdentityConstants.BearerScheme, options =>
                {
                    options.Events ??= new BearerTokenEvents();
                    options.Events.OnMessageReceived = context =>
                    {
                        if (context.Request.Cookies.TryGetValue(AccessTokenCookie, out var cookie)
                            && !string.IsNullOrEmpty(cookie))
                        {
                            context.Token = cookie;
                        }

                        return Task.CompletedTask;
                    };
                });
            });
        });

    private static async Task<string> IssueTokenAsync(WebApplicationFactory<Program> factory, string source)
    {
        var email = $"cookie-token-{source}-{Guid.NewGuid():N}@test.local";
        await TestHelpers.SeedUserAsync(factory, email);
        using var client = factory.CreateClient();
        if (source == "jwt")
        {
            return await TestHelpers.CreateJwtAsync(client, email, TestHelpers.DefaultPassword);
        }

        var (accessToken, _) = await TestHelpers.LoginBearerAsync(client, email, TestHelpers.DefaultPassword);
        return accessToken;
    }

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient client,
        string token,
        bool includeAuthorization,
        bool includeCsrf)
    {
        string? csrf = null;
        var cookies = new List<string>
        {
            $"{AccessTokenCookie}={Uri.EscapeDataString(token)}"
        };

        if (includeCsrf)
        {
            var issued = await GetCsrfAsync(client, token);
            csrf = issued.Token;
            cookies.AddRange(issued.Cookies);
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, "/test/csrf-auth");
        request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", cookies));
        if (includeAuthorization)
        {
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        }

        if (csrf is not null)
        {
            request.Headers.TryAddWithoutValidation("RequestVerificationToken", csrf);
        }

        return await client.SendAsync(request);
    }

    private static async Task<(string Token, IReadOnlyList<string> Cookies)> GetCsrfAsync(HttpClient client, string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/identity/csrfToken");
        request.Headers.TryAddWithoutValidation(
            "Cookie",
            $"{AccessTokenCookie}={Uri.EscapeDataString(accessToken)}");
        var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var token = TestHelpers.TryGetString(doc.RootElement, "csrfToken", "CsrfToken");
        Assert.False(string.IsNullOrEmpty(token));
        return (token!, CookiePairs(response));
    }

    private static List<string> CookiePairs(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return [];
        }

        return values
            .Select(value => value.Split(';', 2)[0].Trim())
            .Where(pair => pair.Length > 0)
            .ToList();
    }
}
