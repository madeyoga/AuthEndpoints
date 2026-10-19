using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using AuthEndpoints.Tests.PublicApi;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.Tests;

public class PasskeyCeremonyAntiforgeryTests
{
    private const string SigningKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";

    public static TheoryData<AuthEndpointsSession, RefreshTokenTransport, bool> Sessions => new()
    {
        { AuthEndpointsSession.Cookie, RefreshTokenTransport.Cookie, true },
        { AuthEndpointsSession.Cookie, RefreshTokenTransport.Body, true },
        { AuthEndpointsSession.IdentityBearer, RefreshTokenTransport.Cookie, false },
        { AuthEndpointsSession.IdentityBearer, RefreshTokenTransport.Body, false },
        { AuthEndpointsSession.Jwt, RefreshTokenTransport.Cookie, true },
        { AuthEndpointsSession.Jwt, RefreshTokenTransport.Body, false },
    };

    [Theory]
    [MemberData(nameof(Sessions))]
    public void Required_FollowsAmbientCredential(
        AuthEndpointsSession session,
        RefreshTokenTransport transport,
        bool required)
    {
        Assert.Equal(required, PasskeyCeremonyAntiforgery.Required(session, transport));
    }

    [Fact]
    public async Task Issue315_WithoutHostAntiforgeryEndpoint_ClientCompletesPasskeyCeremony()
    {
        await AssertJwtBodyCeremonyAsync(mapHostAntiforgeryEndpoint: false);
    }

    [Fact]
    public async Task Issue315_WithHostAntiforgeryEndpoint_ClientCompletesPasskeyCeremony()
    {
        await AssertJwtBodyCeremonyAsync(mapHostAntiforgeryEndpoint: true);
    }

    [Theory]
    [InlineData("/auth/passkeys/requestOptions")]
    [InlineData("/auth/passkeys/register/options")]
    [InlineData("/auth/passkeys/register")]
    [InlineData("/auth/passkeys/login")]
    public async Task CookieSession_CeremonyWithoutToken_Returns400(string path)
    {
        await AssertMissingTokenAsync(AuthEndpointsSession.Cookie, RefreshTokenTransport.Cookie, path);
    }

    [Theory]
    [InlineData("/auth/passkeys/requestOptions")]
    [InlineData("/auth/passkeys/register/options")]
    [InlineData("/auth/passkeys/register")]
    [InlineData("/auth/passkeys/login")]
    public async Task JwtCookieTransport_CeremonyWithoutToken_Returns400(string path)
    {
        await AssertMissingTokenAsync(AuthEndpointsSession.Jwt, RefreshTokenTransport.Cookie, path);
    }

    [Fact]
    public void PasswordJwtBody_PasskeyRoutes_OmitAntiforgeryAndCsrfToken()
    {
        var surface = CapturePassword(AuthEndpointsSession.Jwt, RefreshTokenTransport.Body);
        Assert.DoesNotContain("csrfToken", surface, StringComparison.Ordinal);
        AssertCeremonyAntiforgery(surface, "/auth/passkeys", required: false);
        AssertManagementAntiforgery(surface, "/auth/passkeys");
    }

    [Fact]
    public void PasswordCookie_PasskeyRoutes_RequireAntiforgery()
    {
        var surface = CapturePassword(AuthEndpointsSession.Cookie, RefreshTokenTransport.Cookie);
        Assert.Contains("GET /auth/csrfToken", surface, StringComparison.Ordinal);
        AssertCeremonyAntiforgery(surface, "/auth/passkeys", required: true);
        AssertManagementAntiforgery(surface, "/auth/passkeys");
    }

    [Fact]
    public void PasswordJwtCookieTransport_PasskeyRoutes_RequireAntiforgery()
    {
        var surface = CapturePassword(AuthEndpointsSession.Jwt, RefreshTokenTransport.Cookie);
        Assert.Contains("GET /auth/csrfToken", surface, StringComparison.Ordinal);
        AssertCeremonyAntiforgery(surface, "/auth/passkeys", required: true);
        AssertManagementAntiforgery(surface, "/auth/passkeys");
    }

    [Fact]
    public void IdentityBearerFacade_PasskeyRoutes_OmitAntiforgery()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(AuthEndpointsSignIn.IdentityBearer, options =>
                {
                    options.Passkeys.ServerDomain = "localhost";
                });
            },
            app => app.MapAuthEndpoints<TestAppUser>());

        Assert.DoesNotContain("GET /identity/csrfToken", surface, StringComparison.Ordinal);
        AssertCeremonyAntiforgery(surface, "/account/passkeys", required: false);
        AssertManagementAntiforgery(surface, "/account/passkeys");
    }

    [Fact]
    public void ParameterlessSignInAndSignUp_RequireAntiforgery()
    {
        var signIn = RouteSurface.Capture(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.AddPasskeyEndpoints<TestAppUser>();
            },
            app => app.MapPasskeySignInEndpoints<TestAppUser>());
        AssertCeremonyAntiforgery(signIn, "/passkeys", required: true);

        var signUp = RouteSurface.Capture(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.AddPasskeyEndpoints<TestAppUser>();
            },
            app => app.MapPasskeySignUpEndpoints<TestAppUser>());
        Assert.Contains(
            "POST /passkeys/register name=(none) auth=(none) antiforgery=true rateLimit=AuthEndpoints.Passkey.Register",
            signUp,
            StringComparison.Ordinal);
    }

    [Fact]
    public void SharedRegisterOptions_RequiresAntiforgery()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.AddPasskeyEndpoints<TestAppUser>();
                builder.Services.Configure<JwtSessionOptions>(options =>
                    options.RefreshTokenTransport = RefreshTokenTransport.Body);
            },
            app => app.MapPasskeyRegisterOptionsEndpoints<TestAppUser>());

        Assert.Contains(
            "POST /passkeys/register/options name=(none) auth=(none) antiforgery=true rateLimit=AuthEndpoints.Passkey.ObtainOptions",
            surface,
            StringComparison.Ordinal);
    }

    private static async Task AssertMissingTokenAsync(
        AuthEndpointsSession session,
        RefreshTokenTransport transport,
        string path)
    {
        await using var app = await StartPasswordHostAsync(session, transport, mapHostAntiforgeryEndpoint: false, sqlite: false);
        var http = app.GetTestServer().CreateClient();
        var csrf = await http.GetAsync("/auth/csrfToken");
        Assert.Equal(HttpStatusCode.OK, csrf.StatusCode);

        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(new { email = "ceremony@test.local", credentialJson = "{}" })
        };
        var response = await http.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("Invalid or missing CSRF token.", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    private static async Task AssertJwtBodyCeremonyAsync(bool mapHostAntiforgeryEndpoint)
    {
        var mail = new CapturingEmailSender();
        var databasePath = Path.Combine(Path.GetTempPath(), $"ae-315-{Guid.NewGuid():N}.sqlite");
        await using var app = await StartPasswordHostAsync(
            AuthEndpointsSession.Jwt,
            RefreshTokenTransport.Body,
            mapHostAntiforgeryEndpoint,
            sqlite: true,
            databasePath,
            mail);
        var http = app.GetTestServer().CreateClient();
        var cookies = new CookieContainer();
        var origin = http.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var email = $"passkey-body-{Guid.NewGuid():N}@test.local";
        var authenticator = new SoftwareWebAuthnAuthenticator();

        var libraryCsrf = await SendAsync(http, cookies, HttpMethod.Get, "/auth/csrfToken", body: null, csrfToken: null);
        Assert.Equal(mapHostAntiforgeryEndpoint ? HttpStatusCode.OK : HttpStatusCode.NotFound, libraryCsrf.Status);

        var requestOptions = await PostCeremonyAsync(http, cookies, "/auth/passkeys/requestOptions", new { email }, mapHostAntiforgeryEndpoint);
        Assert.Equal(HttpStatusCode.OK, requestOptions.Status);

        var registerOptions = await PostCeremonyAsync(http, cookies, "/auth/passkeys/register/options", new { email }, mapHostAntiforgeryEndpoint);
        Assert.Equal(HttpStatusCode.OK, registerOptions.Status);
        var credentialJson = authenticator.CreateAttestation(registerOptions.Body, origin);

        var register = await PostCeremonyAsync(
            http,
            cookies,
            "/auth/passkeys/register",
            new { email, credentialJson },
            mapHostAntiforgeryEndpoint);
        Assert.Equal(HttpStatusCode.OK, register.Status);
        using (var registerDoc = JsonDocument.Parse(register.Body))
        {
            Assert.False(string.IsNullOrEmpty(TestHelpers.TryGetString(registerDoc.RootElement, "credentialId", "CredentialId")));
            Assert.True(string.IsNullOrEmpty(TestHelpers.TryGetString(registerDoc.RootElement, "accessToken", "AccessToken")));
        }

        var confirmMail = Assert.Single(mail.Snapshot(), item => item.Email == email && item.Kind == "confirm");
        var confirmPath = new Uri(System.Net.WebUtility.HtmlDecode(confirmMail.Body)).PathAndQuery;
        var confirm = await SendAsync(http, cookies, HttpMethod.Get, confirmPath, body: null, csrfToken: null);
        Assert.Equal(HttpStatusCode.OK, confirm.Status);

        var loginOptions = await PostCeremonyAsync(http, cookies, "/auth/passkeys/requestOptions", new { email }, mapHostAntiforgeryEndpoint);
        Assert.Equal(HttpStatusCode.OK, loginOptions.Status);
        var assertionJson = authenticator.CreateAssertion(loginOptions.Body, origin);
        var login = await PostCeremonyAsync(
            http,
            cookies,
            "/auth/passkeys/login",
            new { credentialJson = assertionJson },
            mapHostAntiforgeryEndpoint);
        Assert.Equal(HttpStatusCode.OK, login.Status);
        Assert.DoesNotContain("AuthEndpoints.Jwt.RefreshToken", login.SetCookie, StringComparison.Ordinal);

        using var loginDoc = JsonDocument.Parse(login.Body);
        var accessToken = TestHelpers.TryGetString(loginDoc.RootElement, "accessToken", "AccessToken");
        var refreshToken = TestHelpers.TryGetString(loginDoc.RootElement, "refreshToken", "RefreshToken");
        Assert.False(string.IsNullOrWhiteSpace(accessToken));
        Assert.False(string.IsNullOrWhiteSpace(refreshToken));

        var verify = await SendAsync(http, cookies, HttpMethod.Get, "/auth/verify", body: null, csrfToken: null, bearer: accessToken);
        Assert.Equal(HttpStatusCode.NoContent, verify.Status);
    }

    private static async Task<Exchange> PostCeremonyAsync(
        HttpClient http,
        CookieContainer cookies,
        string path,
        object body,
        bool csrfAvailable)
    {
        string? csrfToken = null;
        if (csrfAvailable)
        {
            var csrf = await SendAsync(http, cookies, HttpMethod.Get, "/auth/csrfToken", body: null, csrfToken: null);
            csrfToken = ReadCsrfToken(csrf.Body);
            Assert.False(string.IsNullOrEmpty(csrfToken));
        }

        return await SendAsync(http, cookies, HttpMethod.Post, path, body, csrfToken);
    }

    private static async Task<WebApplication> StartPasswordHostAsync(
        AuthEndpointsSession session,
        RefreshTokenTransport transport,
        bool mapHostAntiforgeryEndpoint,
        bool sqlite,
        string? databasePath = null,
        CapturingEmailSender? mail = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.WebHost.UseTestServer();
        if (sqlite)
        {
            builder.Services.AddDbContext<TestDbContext>(o => o.UseSqlite($"Data Source={databasePath}"));
        }
        else
        {
            builder.Services.AddDbContext<TestDbContext>(o =>
                o.UseInMemoryDatabase("passkey-csrf-" + Guid.NewGuid().ToString("N")));
        }

        mail ??= new CapturingEmailSender();
        builder.Services.AddSingleton(mail);
        builder.Services.AddSingleton<IEmailSender<TestAppUser>>(mail);
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(o =>
        {
            o.Session = session;
            o.RequireConfirmedAccount = true;
            o.Passkeys.ServerDomain = "localhost";
            if (session == AuthEndpointsSession.Jwt)
            {
                o.Jwt = jwt =>
                {
                    jwt.SigningOptions.SymmetricKey = SigningKey;
                    jwt.RefreshTokenTransport = transport;
                };
            }
        });

        var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();
        }

        app.UseAuthEndpoints();
        app.MapPasswordAuth<TestAppUser>();
        if (mapHostAntiforgeryEndpoint)
        {
            app.MapGet("/auth/csrfToken", (IAntiforgery antiforgery, HttpContext http) =>
                Results.Ok(new { csrfToken = antiforgery.GetAndStoreTokens(http).RequestToken }));
        }

        await app.StartAsync();
        return app;
    }

    private static string CapturePassword(AuthEndpointsSession session, RefreshTokenTransport transport)
    {
        return RouteSurface.Capture(
            builder =>
            {
                builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
                builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(o =>
                {
                    o.Session = session;
                    o.RequireConfirmedAccount = true;
                    o.Passkeys.ServerDomain = "localhost";
                    if (session == AuthEndpointsSession.Jwt)
                    {
                        o.Jwt = jwt =>
                        {
                            jwt.SigningOptions.SymmetricKey = SigningKey;
                            jwt.RefreshTokenTransport = transport;
                        };
                    }
                });
            },
            app => app.MapPasswordAuth<TestAppUser>());
    }

    private static void AddIdentity(WebApplicationBuilder builder)
    {
        builder.Services
            .AddIdentityApiEndpoints<TestAppUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = true;
                options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            })
            .AddEntityFrameworkStores<TestDbContext>()
            .AddDefaultTokenProviders();
    }

    private static void AssertCeremonyAntiforgery(string surface, string prefix, bool required)
    {
        var flag = required ? "antiforgery=true" : "antiforgery=false";
        string[] routes =
        [
            "POST " + prefix + "/requestOptions",
            "POST " + prefix + "/register/options",
            "POST " + prefix + "/register",
            "POST " + prefix + "/login",
        ];
        foreach (var route in routes)
        {
            var line = surface.Split('\n').Single(item => item.StartsWith(route + " ", StringComparison.Ordinal));
            Assert.Contains(flag, line, StringComparison.Ordinal);
        }
    }

    private static void AssertManagementAntiforgery(string surface, string prefix)
    {
        string[] routes =
        [
            "POST " + prefix + "/creationOptions",
            "POST " + prefix + "/",
            "PATCH " + prefix + "/",
            "DELETE " + prefix + "/{credentialIdUrl}",
        ];
        foreach (var route in routes)
        {
            var line = surface.Split('\n').Single(item => item.StartsWith(route + " ", StringComparison.Ordinal));
            Assert.Contains("antiforgery=true", line, StringComparison.Ordinal);
        }
    }

    private static async Task<Exchange> SendAsync(
        HttpClient http,
        CookieContainer cookies,
        HttpMethod method,
        string path,
        object? body,
        string? csrfToken,
        string? bearer = null)
    {
        using var message = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            message.Content = JsonContent.Create(body);
        }

        var header = cookies.GetCookieHeader(http.BaseAddress!);
        if (!string.IsNullOrEmpty(header))
        {
            message.Headers.TryAddWithoutValidation("Cookie", header);
        }

        if (!string.IsNullOrEmpty(csrfToken))
        {
            message.Headers.TryAddWithoutValidation("RequestVerificationToken", csrfToken);
        }

        if (!string.IsNullOrEmpty(bearer))
        {
            message.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearer);
        }

        message.Headers.TryAddWithoutValidation("Origin", http.BaseAddress!.GetLeftPart(UriPartial.Authority));

        using var response = await http.SendAsync(message);
        if (response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            foreach (var value in values)
            {
                cookies.SetCookies(http.BaseAddress!, value);
            }
        }

        var responseBody = await response.Content.ReadAsStringAsync();
        var setCookie = response.Headers.TryGetValues("Set-Cookie", out var setCookies)
            ? string.Join("\n", setCookies)
            : "";
        return new Exchange(response.StatusCode, responseBody, setCookie);
    }

    private static string? ReadCsrfToken(string body)
    {
        using var doc = JsonDocument.Parse(body);
        return TestHelpers.TryGetString(doc.RootElement, "csrfToken", "CsrfToken");
    }

    private sealed record Exchange(HttpStatusCode Status, string Body, string SetCookie);
}
