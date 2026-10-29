using System.Net;
using System.Text.Json;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests;

public class PasswordAuthTests
{
    private const string SigningKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";

    [Fact]
    public void Options_Defaults()
    {
        var options = new PasswordAuthOptions();
        Assert.Equal(AuthEndpointsSession.Cookie, options.Session);
        Assert.Equal("/auth", options.Path);
        Assert.True(options.RequireConfirmedAccount);
        Assert.True(options.RequireEmailSenderInProduction);
        Assert.Null(options.Jwt);
        Assert.Null(options.ConfigureIdentity);
        Assert.Null(options.Passkeys.ServerDomain);
        Assert.Null(options.EmailConfirmation.ConfirmEmailRedirectUri);
        Assert.Empty(options.EmailConfirmation.AllowedRedirectOrigins);
    }

    [Fact]
    public async Task Cookie_RegisterConfirmLoginManageLogout()
    {
        var mail = new CapturingEmailSender();
        await using var app = await StartAsync(mail, o => o.Session = AuthEndpointsSession.Cookie);
        var http = app.GetTestServer().CreateClient();
        var cookies = new CookieContainer();
        var email = $"password-cookie-{Guid.NewGuid():N}@test.local";

        var register = await SendAsync(http, cookies, () =>
            Post("/auth/register", new { email, password = TestHelpers.DefaultPassword }));
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var tooSoon = await SendAsync(http, cookies, () =>
            Post("/auth/login", new { email, password = TestHelpers.DefaultPassword }));
        Assert.Equal(HttpStatusCode.Unauthorized, tooSoon.StatusCode);

        var confirm = await SendAsync(http, cookies, () => new HttpRequestMessage(HttpMethod.Get, ConfirmPath(mail, email)));
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        Assert.Contains("confirming", await confirm.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);

        var login = await SendAsync(http, cookies, () =>
            Post("/auth/login", new { email, password = TestHelpers.DefaultPassword }));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Contains(".AspNetCore.Identity.Application", CookieHeader(login), StringComparison.Ordinal);

        var info = await SendAsync(http, cookies, () => new HttpRequestMessage(HttpMethod.Get, "/auth/manage/info"));
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);
        using (var infoDoc = JsonDocument.Parse(await info.Content.ReadAsStringAsync()))
        {
            Assert.Equal(email, TestHelpers.TryGetString(infoDoc.RootElement, "email", "Email"));
        }

        var csrf = await CsrfAsync(http, cookies);
        var logout = await SendAsync(http, cookies, () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");
            request.Headers.Add("RequestVerificationToken", csrf);
            return request;
        });
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        var after = await SendAsync(http, cookies, () => new HttpRequestMessage(HttpMethod.Get, "/auth/manage/info"));
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task Jwt_RegisterConfirmCreateManageRefreshLogout()
    {
        var mail = new CapturingEmailSender();
        await using var app = await StartAsync(mail, o =>
        {
            o.Session = AuthEndpointsSession.Jwt;
            o.Jwt = jwt => jwt.SigningOptions.SymmetricKey = SigningKey;
        });
        var http = app.GetTestServer().CreateClient();
        var cookies = new CookieContainer();
        var email = $"password-jwt-{Guid.NewGuid():N}@test.local";

        var register = await SendAsync(http, cookies, () =>
            Post("/auth/register", new { email, password = TestHelpers.DefaultPassword }));
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var tooSoon = await SendAsync(http, cookies, () =>
            Post("/auth/create", new { email, password = TestHelpers.DefaultPassword }));
        Assert.Equal(HttpStatusCode.Unauthorized, tooSoon.StatusCode);

        var confirm = await SendAsync(http, cookies, () => new HttpRequestMessage(HttpMethod.Get, ConfirmPath(mail, email)));
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);

        var create = await SendAsync(http, cookies, () =>
            Post("/auth/create", new { email, password = TestHelpers.DefaultPassword }));
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        using var createDoc = JsonDocument.Parse(await create.Content.ReadAsStringAsync());
        var accessToken = TestHelpers.TryGetString(createDoc.RootElement, "accessToken", "AccessToken");
        Assert.False(string.IsNullOrWhiteSpace(accessToken));
        Assert.Equal("Bearer", TestHelpers.TryGetString(createDoc.RootElement, "tokenType", "TokenType"));
        Assert.Null(TestHelpers.TryGetString(createDoc.RootElement, "refreshToken", "RefreshToken"));
        Assert.Contains("AuthEndpoints.Jwt.RefreshToken", CookieHeader(create), StringComparison.Ordinal);

        var verify = await SendAsync(http, cookies, () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/auth/verify");
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            return request;
        });
        Assert.Equal(HttpStatusCode.NoContent, verify.StatusCode);

        var info = await SendAsync(http, cookies, () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/auth/manage/info");
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            return request;
        });
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);

        var csrf = await CsrfAsync(http, cookies);
        var refresh = await SendAsync(http, cookies, () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/auth/refresh");
            request.Headers.Add("RequestVerificationToken", csrf);
            return request;
        });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        using var refreshDoc = JsonDocument.Parse(await refresh.Content.ReadAsStringAsync());
        var refreshed = TestHelpers.TryGetString(refreshDoc.RootElement, "accessToken", "AccessToken");
        Assert.False(string.IsNullOrWhiteSpace(refreshed));
        Assert.Contains("AuthEndpoints.Jwt.RefreshToken", CookieHeader(refresh), StringComparison.Ordinal);

        var logoutCsrf = await CsrfAsync(http, cookies);
        var logout = await SendAsync(http, cookies, () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");
            request.Headers.Add("RequestVerificationToken", logoutCsrf);
            return request;
        });
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        var replayCsrf = await CsrfAsync(http, cookies);
        var replay = await SendAsync(http, cookies, () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/auth/refresh");
            request.Headers.Add("RequestVerificationToken", replayCsrf);
            return request;
        });
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    [Fact]
    public async Task Jwt_BodyTransport_CreateRefreshLogout_WithoutCookiesOrCsrf()
    {
        var mail = new CapturingEmailSender();
        await using var app = await StartAsync(mail, o =>
        {
            o.Session = AuthEndpointsSession.Jwt;
            o.Jwt = jwt =>
            {
                jwt.SigningOptions.SymmetricKey = SigningKey;
                jwt.RefreshTokenTransport = RefreshTokenTransport.Body;
            };
        });
        var http = app.GetTestServer().CreateClient();
        var email = $"password-jwt-body-{Guid.NewGuid():N}@test.local";

        var register = await SendBareAsync(http, () =>
            Post("/auth/register", new { email, password = TestHelpers.DefaultPassword }));
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var confirm = await SendBareAsync(http, () => new HttpRequestMessage(HttpMethod.Get, ConfirmPath(mail, email)));
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);

        var missingCsrf = await SendBareAsync(http, () => new HttpRequestMessage(HttpMethod.Get, "/auth/csrfToken"));
        Assert.Equal(HttpStatusCode.NotFound, missingCsrf.StatusCode);

        var create = await SendBareAsync(http, () =>
            Post("/auth/create", new { email, password = TestHelpers.DefaultPassword }));
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        Assert.DoesNotContain("AuthEndpoints.Jwt.RefreshToken", CookieHeader(create), StringComparison.Ordinal);
        using var createDoc = JsonDocument.Parse(await create.Content.ReadAsStringAsync());
        var accessToken = TestHelpers.TryGetString(createDoc.RootElement, "accessToken", "AccessToken");
        var refreshToken = TestHelpers.TryGetString(createDoc.RootElement, "refreshToken", "RefreshToken");
        Assert.False(string.IsNullOrWhiteSpace(accessToken));
        Assert.Equal("Bearer", TestHelpers.TryGetString(createDoc.RootElement, "tokenType", "TokenType"));
        Assert.False(string.IsNullOrWhiteSpace(refreshToken));

        var verify = await SendBareAsync(http, () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/auth/verify");
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            return request;
        });
        Assert.Equal(HttpStatusCode.NoContent, verify.StatusCode);

        var refresh = await SendBareAsync(http, () => Post("/auth/refresh", new { refreshToken }));
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        Assert.DoesNotContain("AuthEndpoints.Jwt.RefreshToken", CookieHeader(refresh), StringComparison.Ordinal);
        using var refreshDoc = JsonDocument.Parse(await refresh.Content.ReadAsStringAsync());
        var refreshedAccess = TestHelpers.TryGetString(refreshDoc.RootElement, "accessToken", "AccessToken");
        var refreshed = TestHelpers.TryGetString(refreshDoc.RootElement, "refreshToken", "RefreshToken");
        Assert.False(string.IsNullOrWhiteSpace(refreshedAccess));
        Assert.Equal("Bearer", TestHelpers.TryGetString(refreshDoc.RootElement, "tokenType", "TokenType"));
        Assert.False(string.IsNullOrWhiteSpace(refreshed));
        Assert.NotEqual(refreshToken, refreshed);

        var logout = await SendBareAsync(http, () => Post("/auth/logout", new { refreshToken = refreshed }));
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        var replay = await SendBareAsync(http, () => Post("/auth/refresh", new { refreshToken = refreshed }));
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    [Fact]
    public async Task ConfirmEmailRedirect_UsesPasswordAuthOptions()
    {
        var mail = new CapturingEmailSender();
        await using var app = await StartAsync(mail, o =>
        {
            o.EmailConfirmation.ConfirmEmailRedirectUri = "/done";
        });
        var http = app.GetTestServer().CreateClient();
        var cookies = new CookieContainer();
        var email = $"password-redirect-{Guid.NewGuid():N}@test.local";

        var register = await SendAsync(http, cookies, () =>
            Post("/auth/register", new { email, password = TestHelpers.DefaultPassword }));
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var confirm = await SendAsync(http, cookies, () => new HttpRequestMessage(HttpMethod.Get, ConfirmPath(mail, email)));
        Assert.Equal(HttpStatusCode.Redirect, confirm.StatusCode);
        var location = confirm.Headers.Location?.ToString() ?? "";
        Assert.Contains("/done", location, StringComparison.Ordinal);
        Assert.Contains("status=confirmed", location, StringComparison.Ordinal);
        Assert.Contains("flow=confirm", location, StringComparison.Ordinal);
    }

    [Fact]
    public void Jwt_WithoutCallback_FailsValidation()
    {
        using var app = Build(o => o.Session = AuthEndpointsSession.Jwt);
        var ex = Assert.ThrowsAny<Exception>(() =>
            _ = app.Services.GetRequiredService<IOptions<PasswordAuthOptions>>().Value);
        Assert.Contains("Jwt", ex.ToString(), StringComparison.Ordinal);
        Assert.Contains("requires", ex.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Jwt_CallbackWithoutSigningKey_FailsAtRegistration()
    {
        var builder = NewBuilder();
        var ex = Assert.ThrowsAny<Exception>(() =>
            builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(o =>
            {
                o.Session = AuthEndpointsSession.Jwt;
                o.Jwt = _ => { };
            }));
        Assert.Contains("SymmetricKey", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void IdentityBearer_FailsValidation()
    {
        using var app = Build(o => o.Session = AuthEndpointsSession.IdentityBearer);
        var ex = Assert.ThrowsAny<Exception>(() =>
            _ = app.Services.GetRequiredService<IOptions<PasswordAuthOptions>>().Value);
        Assert.Contains("IdentityBearer", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void UndefinedSession_FailsValidation()
    {
        using var app = Build(o => o.Session = (AuthEndpointsSession)9);
        var ex = Assert.ThrowsAny<Exception>(() =>
            _ = app.Services.GetRequiredService<IOptions<PasswordAuthOptions>>().Value);
        Assert.Contains("Session", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Path_MustBeRooted()
    {
        using var app = Build(o => o.Path = "auth");
        var ex = Assert.ThrowsAny<Exception>(() =>
            _ = app.Services.GetRequiredService<IOptions<PasswordAuthOptions>>().Value);
        Assert.Contains("Path", ex.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TogetherWithAddAuthEndpoints_FailsValidation(bool passwordFirst)
    {
        var builder = NewBuilder();
        builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
        if (passwordFirst)
        {
            builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>();
            builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(o => o.Passkeys.Enabled = false);
        }
        else
        {
            builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(o => o.Passkeys.Enabled = false);
            builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>();
        }

        using var app = builder.Build();
        var password = Assert.ThrowsAny<Exception>(() =>
            _ = app.Services.GetRequiredService<IOptions<PasswordAuthOptions>>().Value);
        var compat = Assert.ThrowsAny<Exception>(() =>
            _ = app.Services.GetRequiredService<IOptions<AuthEndpointsOptions>>().Value);
        Assert.Contains("cannot be used in the same host", password.ToString(), StringComparison.Ordinal);
        Assert.Contains("cannot be used in the same host", compat.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Production_MissingEmailSender_FailsValidation()
    {
        using var app = Build(o => o.Passkeys.ServerDomain = "example.com", Environments.Production);
        var ex = Assert.ThrowsAny<Exception>(() =>
            _ = app.Services.GetRequiredService<IOptions<PasswordAuthOptions>>().Value);
        Assert.Contains("IEmailSender", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Production_WithoutPasskeys_AllowsMissingServerDomain()
    {
        var builder = NewBuilder(Environments.Production);
        builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>();
        using var app = builder.Build();

        var options = app.Services.GetRequiredService<IOptions<PasswordAuthOptions>>().Value;
        Assert.Null(options.Passkeys.ServerDomain);
        Assert.Equal(AuthEndpointsSession.Cookie, options.Session);
    }

    [Fact]
    public void Production_BlankPasskeyDomain_FailsValidation()
    {
        var builder = NewBuilder(Environments.Production);
        builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(o => o.Passkeys.ServerDomain = "  ");
        using var app = builder.Build();

        var ex = Assert.ThrowsAny<Exception>(() =>
            _ = app.Services.GetRequiredService<IOptions<PasswordAuthOptions>>().Value);
        Assert.Contains("ServerDomain", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Production_AbsoluteConfirmRedirectWithoutAllowlist_FailsValidation()
    {
        var builder = NewBuilder(Environments.Production);
        builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(o =>
            o.EmailConfirmation.ConfirmEmailRedirectUri = "https://spa.example.com/confirmed");
        using var app = builder.Build();

        var ex = Assert.ThrowsAny<Exception>(() =>
            _ = app.Services.GetRequiredService<IOptions<PasswordAuthOptions>>().Value);
        Assert.Contains("AllowedRedirectOrigins", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Map_WithoutAdd_Throws()
    {
        var builder = NewBuilder();
        using var app = builder.Build();
        var ex = Assert.Throws<InvalidOperationException>(() => app.MapPasswordAuth<TestAppUser>());
        Assert.Contains("AddPasswordAuth", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddPasswordAuth_Twice_Throws()
    {
        var builder = NewBuilder();
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>());
        Assert.Contains("already called", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LaterConfigure_EmailConfirmation_IsCopiedAndRegistrationStays()
    {
        var builder = NewBuilder();
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(o => o.Passkeys.ServerDomain = "localhost");
        builder.Services.Configure<PasswordAuthOptions>(o =>
        {
            o.EmailConfirmation.ConfirmEmailRedirectUri = "/later";
            o.EmailConfirmation.AllowedRedirectOrigins.Add("https://app.example.com");
        });
        using var app = builder.Build();

        var registration = app.Services.GetRequiredService<PasswordAuthRegistration>();
        Assert.Equal(AuthEndpointsSession.Cookie, registration.Session);
        Assert.Equal("/auth", registration.Path);
        Assert.Equal("localhost", registration.ServerDomain);

        var password = app.Services.GetRequiredService<IOptions<PasswordAuthOptions>>().Value;
        var auth = app.Services.GetRequiredService<IOptions<AuthEndpointsOptions>>().Value;
        Assert.Equal("/later", password.EmailConfirmation.ConfirmEmailRedirectUri);
        Assert.Equal("/later", auth.EmailConfirmation.ConfirmEmailRedirectUri);
        Assert.Contains("https://app.example.com", auth.EmailConfirmation.AllowedRedirectOrigins);
        app.MapPasswordAuth<TestAppUser>();
    }

    [Theory]
    [InlineData("Session")]
    [InlineData("Path")]
    [InlineData("Passkeys.ServerDomain")]
    public void LaterConfigure_ChangingRegistrationFields_FailsValidationAndMap(string field)
    {
        var builder = NewBuilder();
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(o => o.Passkeys.ServerDomain = "localhost");
        builder.Services.Configure<PasswordAuthOptions>(o =>
        {
            if (field == "Session")
            {
                o.Session = AuthEndpointsSession.Jwt;
            }
            else if (field == "Path")
            {
                o.Path = "/other";
            }
            else
            {
                o.Passkeys.ServerDomain = "example.com";
            }
        });
        using var app = builder.Build();

        var registration = app.Services.GetRequiredService<PasswordAuthRegistration>();
        Assert.Equal(AuthEndpointsSession.Cookie, registration.Session);
        Assert.Equal("/auth", registration.Path);
        Assert.Equal("localhost", registration.ServerDomain);

        var resolved = Assert.ThrowsAny<Exception>(() =>
            _ = app.Services.GetRequiredService<IOptions<PasswordAuthOptions>>().Value);
        Assert.Contains("changed " + field, resolved.ToString(), StringComparison.Ordinal);

        var mapped = Assert.ThrowsAny<Exception>(() => app.MapPasswordAuth<TestAppUser>());
        Assert.Contains("changed " + field, mapped.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void AddPasswordAuth_Roles_ResolvesRoleStoreWithoutRemoveAll()
    {
        var builder = NewRolesBuilder();
        builder.Services.AddPasswordAuth<TestAppUser, IdentityRole, TestRolesDbContext>();

        using var app = builder.Build();
        using var scope = app.Services.CreateScope();
        var services = scope.ServiceProvider;

        var store = services.GetRequiredService<IUserStore<TestAppUser>>();
        Assert.IsAssignableFrom<IUserRoleStore<TestAppUser>>(store);
        Assert.NotNull(services.GetRequiredService<RoleManager<IdentityRole>>());
        Assert.IsType<UserClaimsPrincipalFactory<TestAppUser, IdentityRole>>(
            services.GetRequiredService<IUserClaimsPrincipalFactory<TestAppUser>>());
    }

    [Fact]
    public void AddPasswordAuth_WithoutRoles_ResolvesUserOnlyStore()
    {
        var builder = NewBuilder();
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>();

        using var app = builder.Build();
        using var scope = app.Services.CreateScope();
        var services = scope.ServiceProvider;

        var store = services.GetRequiredService<IUserStore<TestAppUser>>();
        Assert.IsNotAssignableFrom<IUserRoleStore<TestAppUser>>(store);
        Assert.Null(services.GetService<RoleManager<IdentityRole>>());
        Assert.IsType<UserClaimsPrincipalFactory<TestAppUser>>(
            services.GetRequiredService<IUserClaimsPrincipalFactory<TestAppUser>>());
    }

    [Fact]
    public async Task CookieLogin_RoleClaim_AllowsRequireRole()
    {
        await using var app = await StartRolesAsync();
        var http = app.GetTestServer().CreateClient();
        var memberEmail = $"role-member-{Guid.NewGuid():N}@test.local";
        var otherEmail = $"role-other-{Guid.NewGuid():N}@test.local";
        await SeedRoleUserAsync(app, memberEmail, "Admin");
        await SeedRoleUserAsync(app, otherEmail, role: null);

        var memberCookies = new CookieContainer();
        var memberLogin = await SendAsync(http, memberCookies, () =>
            Post("/auth/login", new { email = memberEmail, password = TestHelpers.DefaultPassword }));
        Assert.Equal(HttpStatusCode.OK, memberLogin.StatusCode);
        Assert.Contains(".AspNetCore.Identity.Application", CookieHeader(memberLogin), StringComparison.Ordinal);

        var member = await SendAsync(http, memberCookies, () => new HttpRequestMessage(HttpMethod.Get, "/admin"));
        Assert.Equal(HttpStatusCode.OK, member.StatusCode);

        var otherCookies = new CookieContainer();
        var otherLogin = await SendAsync(http, otherCookies, () =>
            Post("/auth/login", new { email = otherEmail, password = TestHelpers.DefaultPassword }));
        Assert.Equal(HttpStatusCode.OK, otherLogin.StatusCode);

        var other = await SendAsync(http, otherCookies, () => new HttpRequestMessage(HttpMethod.Get, "/admin"));
        Assert.Equal(HttpStatusCode.Forbidden, other.StatusCode);
    }

    private static WebApplicationBuilder NewBuilder(string environment = "Development")
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = environment,
        });
        builder.WebHost.UseTestServer();
        var databaseName = "password-auth-" + Guid.NewGuid().ToString("N");
        builder.Services.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase(databaseName));
        return builder;
    }

    private static WebApplicationBuilder NewRolesBuilder()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Development",
        });
        builder.WebHost.UseTestServer();
        var databaseName = "password-auth-roles-" + Guid.NewGuid().ToString("N");
        builder.Services.AddDbContext<TestRolesDbContext>(o => o.UseInMemoryDatabase(databaseName));
        return builder;
    }

    private static WebApplication Build(Action<PasswordAuthOptions> configure, string environment = "Development")
    {
        var builder = NewBuilder(environment);
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(configure);
        return builder.Build();
    }

    private static async Task<WebApplication> StartAsync(CapturingEmailSender mail, Action<PasswordAuthOptions> configure)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Development",
        });
        builder.WebHost.UseTestServer();
        var path = Path.Combine(Path.GetTempPath(), $"ae-password-auth-{Guid.NewGuid():N}.sqlite");
        builder.Services.AddDbContext<TestDbContext>(o => o.UseSqlite($"Data Source={path}"));
        builder.Services.AddSingleton(mail);
        builder.Services.AddSingleton<IEmailSender<TestAppUser>>(mail);
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(configure);
        var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();
        }

        app.UseAuthEndpoints();
        app.MapPasswordAuth<TestAppUser>();
        await app.StartAsync();
        return app;
    }

    private static async Task<WebApplication> StartRolesAsync()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Development",
        });
        builder.WebHost.UseTestServer();
        var path = Path.Combine(Path.GetTempPath(), $"ae-password-auth-roles-{Guid.NewGuid():N}.sqlite");
        builder.Services.AddDbContext<TestRolesDbContext>(o => o.UseSqlite($"Data Source={path}"));
        builder.Services.AddPasswordAuth<TestAppUser, IdentityRole, TestRolesDbContext>();
        var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TestRolesDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();
        }

        app.UseAuthEndpoints();
        app.MapPasswordAuth<TestAppUser>();
        app.MapGet("/admin", () => Results.Ok())
            .RequireAuthorization(policy => policy.RequireRole("Admin"));
        await app.StartAsync();
        return app;
    }

    private static async Task SeedRoleUserAsync(WebApplication app, string email, string? role)
    {
        using var scope = app.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = new TestAppUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
        };
        var created = await users.CreateAsync(user, TestHelpers.DefaultPassword);
        Assert.True(created.Succeeded, string.Join(", ", created.Errors.Select(error => error.Description)));
        if (role is null)
        {
            return;
        }

        var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        if (!await roles.RoleExistsAsync(role))
        {
            var roleResult = await roles.CreateAsync(new IdentityRole(role));
            Assert.True(roleResult.Succeeded, string.Join(", ", roleResult.Errors.Select(error => error.Description)));
        }

        var added = await users.AddToRoleAsync(user, role);
        Assert.True(added.Succeeded, string.Join(", ", added.Errors.Select(error => error.Description)));
    }

    private static HttpRequestMessage Post(string path, object body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body),
        };
        return request;
    }

    private static async Task<string> CsrfAsync(HttpClient http, CookieContainer cookies)
    {
        var response = await SendAsync(http, cookies, () => new HttpRequestMessage(HttpMethod.Get, "/auth/csrfToken"));
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return TestHelpers.TryGetString(doc.RootElement, "csrfToken", "CsrfToken")
            ?? throw new InvalidOperationException("csrfToken was missing.");
    }

    private static string ConfirmPath(CapturingEmailSender mail, string email)
    {
        var item = Assert.Single(mail.Snapshot(), message => message.Email == email && message.Kind == "confirm");
        var url = System.Net.WebUtility.HtmlDecode(item.Body);
        return new Uri(url).PathAndQuery;
    }

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient http,
        CookieContainer cookies,
        Func<HttpRequestMessage> request)
    {
        using var message = request();
        var header = cookies.GetCookieHeader(http.BaseAddress!);
        if (!string.IsNullOrEmpty(header))
        {
            message.Headers.TryAddWithoutValidation("Cookie", header);
        }

        if (http.BaseAddress is not null && !message.Headers.Contains("Origin"))
        {
            message.Headers.TryAddWithoutValidation("Origin", http.BaseAddress.GetLeftPart(UriPartial.Authority));
        }

        var response = await http.SendAsync(message);
        if (response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            foreach (var value in values)
            {
                cookies.SetCookies(http.BaseAddress!, value);
            }
        }

        return response;
    }

    private static async Task<HttpResponseMessage> SendBareAsync(HttpClient http, Func<HttpRequestMessage> request)
    {
        using var message = request();
        Assert.False(message.Headers.Contains("Cookie"));
        Assert.False(message.Headers.Contains("RequestVerificationToken"));
        if (http.BaseAddress is not null && !message.Headers.Contains("Origin"))
        {
            message.Headers.TryAddWithoutValidation("Origin", http.BaseAddress.GetLeftPart(UriPartial.Authority));
        }

        return await http.SendAsync(message);
    }

    private static string CookieHeader(HttpResponseMessage response)
    {
        return response.Headers.TryGetValues("Set-Cookie", out var values)
            ? string.Join("\n", values)
            : "";
    }
}
