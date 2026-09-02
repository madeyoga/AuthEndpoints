using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests;

public class AuthEndpointsFacadeTests
{
    [Fact]
    public async Task Facade_RegisterAndLogin_CookieIdentityWorks()
    {
        await using var host = await StartFacadeHostAsync(o =>
        {
            o.Passkeys.ServerDomain = "localhost";
            o.ConfigureIdentity = identity =>
            {
                identity.SignIn.RequireConfirmedAccount = false;
                identity.Password.RequireDigit = false;
                identity.Password.RequireLowercase = false;
                identity.Password.RequireUppercase = false;
                identity.Password.RequireNonAlphanumeric = false;
                identity.Password.RequiredLength = 6;
            };
        });

        var server = host.GetTestServer();
        using var http = server.CreateClient();
        var cookies = new CookieContainer();

        var email = $"facade-{Guid.NewGuid():N}@test.local";
        var register = await SendWithCookiesAsync(http, cookies, () =>
            http.PostAsJsonAsync("/identity/register", new
            {
                email,
                password = TestHelpers.DefaultPassword
            }));
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var login = await SendWithCookiesAsync(http, cookies, () =>
            http.PostAsJsonAsync("/identity/login", new
            {
                email,
                password = TestHelpers.DefaultPassword
            }));
        Assert.True(
            login.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
            $"Login failed: {(int)login.StatusCode} {await login.Content.ReadAsStringAsync()}");

        using var infoRequest = new HttpRequestMessage(HttpMethod.Get, "/identity/manage/info");
        ApplyCookies(infoRequest, cookies, http.BaseAddress!);
        var info = await http.SendAsync(infoRequest);
        CaptureCookies(info, cookies, http.BaseAddress!);
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);
    }

    [Fact]
    public void Facade_Production_MissingPasskeyServerDomain_FailsValidation()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Production
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(o =>
            o.UseInMemoryDatabase("FacadeProdDomain_" + Guid.NewGuid().ToString("N")));
        builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(o =>
        {
            o.Passkeys.Enabled = true;
            o.Passkeys.ServerDomain = null;
            o.RequireEmailSenderInProduction = false;
        });
        builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();

        using var app = builder.Build();
        app.UseAuthEndpoints();

        var ex = Assert.ThrowsAny<Exception>(() => app.MapAuthEndpoints<TestAppUser>());
        Assert.Contains("ServerDomain", ex.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Facade_Production_NoOpEmailSender_FailsValidation()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Production
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(o =>
            o.UseInMemoryDatabase("FacadeProdEmail_" + Guid.NewGuid().ToString("N")));
        builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(o =>
        {
            o.Passkeys.ServerDomain = "example.com";
            o.RequireEmailSenderInProduction = true;
        });

        using var app = builder.Build();

        var ex = Assert.ThrowsAny<Exception>(() =>
        {
            _ = app.Services.GetRequiredService<IOptions<AuthEndpointsOptions>>().Value;
        });
        Assert.Contains("IEmailSender", ex.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Facade_Options_DefaultPaths()
    {
        var options = new AuthEndpointsOptions();
        Assert.Equal("/identity", options.IdentityPath);
        Assert.Equal("/account", options.PasskeyPath);
        Assert.True(options.RequireConfirmedAccount);
        Assert.True(options.Passkeys.Enabled);
        Assert.True(options.RequireEmailSenderInProduction);
        Assert.False(options.Jwt.Enabled);
        Assert.Equal("/auth", options.Jwt.Path);
        Assert.Equal(AuthEndpointsSignIn.Cookie, options.SignIn);
    }

    [Fact]
    public async Task Facade_Bearer_RegisterAndLogin_ReturnsTokensAndManageInfo()
    {
        await using var host = await StartFacadeHostAsync(o =>
        {
            o.Passkeys.ServerDomain = "localhost";
            o.ConfigureIdentity = RelaxIdentityForTests;
        }, bearer: true);

        var server = host.GetTestServer();
        using var http = server.CreateClient();

        var email = $"facade-bearer-{Guid.NewGuid():N}@test.local";
        var register = await http.PostAsJsonAsync("/identity/register", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var login = await http.PostAsJsonAsync("/identity/login", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        using var loginDoc = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        var accessToken = TestHelpers.TryGetString(loginDoc.RootElement, "accessToken", "AccessToken");
        var refreshToken = TestHelpers.TryGetString(loginDoc.RootElement, "refreshToken", "RefreshToken");
        Assert.False(string.IsNullOrWhiteSpace(accessToken));
        Assert.False(string.IsNullOrWhiteSpace(refreshToken));

        using var infoRequest = new HttpRequestMessage(HttpMethod.Get, "/identity/manage/info");
        infoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var info = await http.SendAsync(infoRequest);
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);
        using var infoDoc = JsonDocument.Parse(await info.Content.ReadAsStringAsync());
        Assert.Equal(email, TestHelpers.TryGetString(infoDoc.RootElement, "email", "Email"));
    }

    [Fact]
    public async Task Facade_Bearer_Refresh_ReturnsNewAccessToken()
    {
        await using var host = await StartFacadeHostAsync(o =>
        {
            o.Passkeys.ServerDomain = "localhost";
            o.ConfigureIdentity = RelaxIdentityForTests;
        }, bearer: true);

        var server = host.GetTestServer();
        using var http = server.CreateClient();

        var email = $"facade-bearer-refresh-{Guid.NewGuid():N}@test.local";
        var register = await http.PostAsJsonAsync("/identity/register", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var login = await http.PostAsJsonAsync("/identity/login", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using var loginDoc = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        var refreshToken = TestHelpers.TryGetString(loginDoc.RootElement, "refreshToken", "RefreshToken");
        Assert.False(string.IsNullOrWhiteSpace(refreshToken));

        var refresh = await http.PostAsJsonAsync("/identity/refresh", new { refreshToken });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        using var refreshDoc = JsonDocument.Parse(await refresh.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrWhiteSpace(
            TestHelpers.TryGetString(refreshDoc.RootElement, "accessToken", "AccessToken")));
    }

    [Fact]
    public async Task Facade_Bearer_CsrfToken_IsNotMapped()
    {
        await using var host = await StartFacadeHostAsync(o =>
        {
            o.Passkeys.ServerDomain = "localhost";
            o.ConfigureIdentity = RelaxIdentityForTests;
        }, bearer: true);

        var server = host.GetTestServer();
        using var http = server.CreateClient();
        var csrf = await http.GetAsync("/identity/csrfToken");
        Assert.Equal(HttpStatusCode.NotFound, csrf.StatusCode);
    }

    [Fact]
    public async Task Facade_SignInOption_MapsBearerLogin()
    {
        await using var host = await StartFacadeHostAsync(o =>
        {
            o.Passkeys.ServerDomain = "localhost";
            o.ConfigureIdentity = RelaxIdentityForTests;
            o.SignIn = AuthEndpointsSignIn.IdentityBearer;
        });

        var server = host.GetTestServer();
        using var http = server.CreateClient();

        var email = $"facade-signin-opt-{Guid.NewGuid():N}@test.local";
        var register = await http.PostAsJsonAsync("/identity/register", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var login = await http.PostAsJsonAsync("/identity/login", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using var loginDoc = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrWhiteSpace(
            TestHelpers.TryGetString(loginDoc.RootElement, "accessToken", "AccessToken")));
    }

    [Fact]
    public void Facade_Bearer_WithRoles_ResolvesRoleStore()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestRolesDbContext>(o =>
            o.UseInMemoryDatabase("FacadeBearerRoles_" + Guid.NewGuid().ToString("N")));
        builder.Services.AddAuthEndpoints<TestAppUser, IdentityRole, TestRolesDbContext>(
            AuthEndpointsSignIn.IdentityBearer,
            o =>
            {
                o.Passkeys.ServerDomain = "localhost";
                o.RequireEmailSenderInProduction = false;
            });
        builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();

        using var app = builder.Build();
        using var scope = app.Services.CreateScope();
        var sp = scope.ServiceProvider;

        Assert.NotNull(sp.GetRequiredService<IRoleStore<IdentityRole>>());
        Assert.NotNull(sp.GetRequiredService<RoleManager<IdentityRole>>());
        Assert.Equal(
            AuthEndpointsSignIn.IdentityBearer,
            sp.GetRequiredService<IOptions<AuthEndpointsOptions>>().Value.SignIn);
    }

    [Fact]
    public async Task Facade_JwtEnabled_MapsCreateEndpoint()
    {
        await using var host = await StartFacadeHostAsync(o =>
        {
            o.Passkeys.ServerDomain = "localhost";
            o.ConfigureIdentity = identity =>
            {
                identity.SignIn.RequireConfirmedAccount = false;
                identity.Password.RequireDigit = false;
                identity.Password.RequireLowercase = false;
                identity.Password.RequireUppercase = false;
                identity.Password.RequireNonAlphanumeric = false;
                identity.Password.RequiredLength = 6;
            };
            o.Jwt.Enabled = true;
            o.Jwt.Path = "/auth";
            o.Jwt.Configure = jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            };
        });

        var server = host.GetTestServer();
        using var http = server.CreateClient();

        var email = $"facade-jwt-{Guid.NewGuid():N}@test.local";
        var register = await http.PostAsJsonAsync("/identity/register", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var create = await http.PostAsJsonAsync("/auth/create", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
    }

    [Fact]
    public void Facade_WithRoles_ResolvesRoleStore()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestRolesDbContext>(o =>
            o.UseInMemoryDatabase("FacadeRoles_" + Guid.NewGuid().ToString("N")));
        builder.Services.AddAuthEndpoints<TestAppUser, IdentityRole, TestRolesDbContext>(o =>
        {
            o.Passkeys.ServerDomain = "localhost";
            o.RequireEmailSenderInProduction = false;
        });
        builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();

        using var app = builder.Build();
        using var scope = app.Services.CreateScope();
        var sp = scope.ServiceProvider;

        Assert.NotNull(sp.GetRequiredService<IRoleStore<IdentityRole>>());
        Assert.NotNull(sp.GetRequiredService<RoleManager<IdentityRole>>());
    }

    private static void RelaxIdentityForTests(IdentityOptions identity)
    {
        identity.SignIn.RequireConfirmedAccount = false;
        identity.Password.RequireDigit = false;
        identity.Password.RequireLowercase = false;
        identity.Password.RequireUppercase = false;
        identity.Password.RequireNonAlphanumeric = false;
        identity.Password.RequiredLength = 6;
    }

    private static async Task<WebApplication> StartFacadeHostAsync(
        Action<AuthEndpointsOptions>? configure = null,
        bool bearer = false)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.WebHost.UseTestServer();

        var dbName = "FacadeHost_" + Guid.NewGuid().ToString("N");
        builder.Services.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase(dbName));
        if (bearer)
        {
            builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(
                AuthEndpointsSignIn.IdentityBearer,
                o =>
                {
                    o.Passkeys.ServerDomain = "localhost";
                    configure?.Invoke(o);
                });
        }
        else
        {
            builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(o =>
            {
                o.Passkeys.ServerDomain = "localhost";
                configure?.Invoke(o);
            });
        }

        builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();

        var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            await db.Database.EnsureCreatedAsync();
        }

        app.UseAuthEndpoints();
        app.MapAuthEndpoints<TestAppUser>();
        await app.StartAsync();
        return app;
    }

    private static async Task<HttpResponseMessage> SendWithCookiesAsync(
        HttpClient http,
        CookieContainer cookies,
        Func<Task<HttpResponseMessage>> send)
    {
        ApplyDefaultCookieHeader(http, cookies);
        var response = await send();
        CaptureCookies(response, cookies, http.BaseAddress!);
        ApplyDefaultCookieHeader(http, cookies);
        return response;
    }

    private static void ApplyDefaultCookieHeader(HttpClient http, CookieContainer cookies)
    {
        http.DefaultRequestHeaders.Remove("Cookie");
        var header = cookies.GetCookieHeader(http.BaseAddress!);
        if (!string.IsNullOrEmpty(header))
        {
            http.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", header);
        }
    }

    private static void ApplyCookies(HttpRequestMessage request, CookieContainer cookies, Uri baseAddress)
    {
        var header = cookies.GetCookieHeader(baseAddress);
        if (!string.IsNullOrEmpty(header))
        {
            request.Headers.TryAddWithoutValidation("Cookie", header);
        }
    }

    private static void CaptureCookies(HttpResponseMessage response, CookieContainer cookies, Uri baseAddress)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return;
        }

        foreach (var value in values)
        {
            cookies.SetCookies(baseAddress, value);
        }
    }
}
