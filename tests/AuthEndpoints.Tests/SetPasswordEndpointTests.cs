using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.ReAuth;
using AuthEndpoints.Tests.PublicApi;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Tests;

public class SetPasswordEndpointTests
{
    [Fact]
    public async Task SetPassword_WithoutReAuth_Returns403()
    {
        await using var host = await PasswordHost.StartAsync();
        var email = Email();
        await host.SeedWithoutPasswordAsync(email);
        var jar = await host.SignInCookieAsync(email);

        var response = await host.PostAsync(jar, "/identity/manage/password", new { newPassword = "SetPass1!" }, csrf: true);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(await host.HasPasswordAsync(email));
        Assert.DoesNotContain(host.Mail.Snapshot(), item => item.Kind == "security" && item.Email == email);
    }

    [Fact]
    public async Task SetPassword_WithReAuth_SetsPassword_EndsOtherSessions_AndNotifies()
    {
        await using var host = await PasswordHost.StartAsync();
        var email = Email();
        await host.SeedWithoutPasswordAsync(email);
        var actor = await host.SignInCookieAsync(email);
        var otherCookie = await host.SignInCookieAsync(email);
        var bearer = await host.SignInBearerAsync(email);
        var stamp = await host.StampAsync(email);

        var denied = await host.PostAsync(actor, "/identity/manage/password", new { newPassword = "SetPass1!" }, csrf: true);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        await host.ConfirmEmailCodeAsync(actor, email);
        var missingCsrf = await host.PostAsync(actor, "/identity/manage/password", new { newPassword = "SetPass1!" }, csrf: false);
        Assert.Equal(HttpStatusCode.BadRequest, missingCsrf.StatusCode);
        Assert.Contains("Invalid or missing CSRF token.", await missingCsrf.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var set = await host.PostAsync(actor, "/identity/manage/password", new { newPassword = "SetPass1!" }, csrf: true);
        Assert.Equal(HttpStatusCode.OK, set.StatusCode);
        Assert.True(await host.HasPasswordAsync(email));
        Assert.NotEqual(stamp, await host.StampAsync(email));
        Assert.Contains(host.Mail.Snapshot(), item => item.Kind == "security" && item.Email == email && item.Body == "password-set");

        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync(actor, "/identity/manage/info")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetAsync(otherCookie, "/identity/manage/info")).StatusCode);

        await host.ConfirmPasswordAsync(actor, "SetPass1!");
        var again = await host.PostAsync(actor, "/identity/manage/password", new { newPassword = "Another1!" }, csrf: true);
        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
        Assert.Contains("UserAlreadyHasPassword", await again.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var refresh = await host.Client.PostAsJsonAsync("/mobile/refresh", new { refreshToken = bearer.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);

        var login = new CookieJar();
        var signedIn = await host.PostAsync(login, "/identity/login", new { email, password = "SetPass1!" }, csrf: false);
        Assert.True(
            signedIn.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
            $"Password login failed: {(int)signedIn.StatusCode} {await signedIn.Content.ReadAsStringAsync()}");
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync(login, "/identity/manage/info")).StatusCode);
    }

    [Fact]
    public async Task SetPassword_WhenPasswordExists_Returns400()
    {
        await using var host = await PasswordHost.StartAsync();
        var email = Email();
        await host.SeedWithPasswordAsync(email, "Passw0rd!");
        var jar = await host.SignInPasswordAsync(email, "Passw0rd!");
        await host.ConfirmPasswordAsync(jar, "Passw0rd!");

        var response = await host.PostAsync(jar, "/identity/manage/password", new { newPassword = "SetPass1!" }, csrf: true);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("UserAlreadyHasPassword", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.DoesNotContain(host.Mail.Snapshot(), item => item.Kind == "security" && item.Email == email);

        var login = new CookieJar();
        var still = await host.PostAsync(login, "/identity/login", new { email, password = "Passw0rd!" }, csrf: false);
        Assert.True(still.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task SetPassword_WhenPasswordIsWeak_Returns400_AndLeavesHasPasswordFalse()
    {
        await using var host = await PasswordHost.StartAsync();
        var email = Email();
        await host.SeedWithoutPasswordAsync(email);
        var jar = await host.SignInCookieAsync(email);
        await host.ConfirmEmailCodeAsync(jar, email);

        var response = await host.PostAsync(jar, "/identity/manage/password", new { newPassword = "abc" }, csrf: true);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode} {body}");
        Assert.Contains("PasswordTooShort", body, StringComparison.Ordinal);
        Assert.False(await host.HasPasswordAsync(email));
        Assert.DoesNotContain(host.Mail.Snapshot(), item => item.Kind == "security" && item.Email == email);
    }

    [Fact]
    public async Task SetPassword_WhenPasswordSignInUnmapped_Returns404()
    {
        await using var host = await PasswordHost.StartAsync(mapPasswordSignIn: false);
        var anonymous = await host.PostAsync(new CookieJar(), "/identity/manage/password", new { newPassword = "SetPass1!" }, csrf: false);
        Assert.Equal(HttpStatusCode.NotFound, anonymous.StatusCode);

        var email = Email();
        await host.SeedWithoutPasswordAsync(email);
        var jar = await host.SignInCookieAsync(email);
        await host.ConfirmEmailCodeAsync(jar, email);
        var signedIn = await host.PostAsync(jar, "/identity/manage/password", new { newPassword = "SetPass1!" }, csrf: true);
        Assert.Equal(HttpStatusCode.NotFound, signedIn.StatusCode);
        Assert.False(await host.HasPasswordAsync(email));
        Assert.DoesNotContain(host.Mail.Snapshot(), item => item.Kind == "security");
    }

    [Fact]
    public async Task SetPassword_Anonymous_WhenPasswordSignInMapped_Returns401()
    {
        await using var host = await PasswordHost.StartAsync();
        var response = await host.PostAsync(new CookieJar(), "/identity/manage/password", new { newPassword = "SetPass1!" }, csrf: false);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public void SetPassword_RouteRequiresSignInAntiforgeryAndReAuth_AndFacadeOmitsIt()
    {
        using var mapped = RouteSurface.Build(
            builder =>
            {
                builder.Services
                    .AddIdentityApiEndpoints<TestAppUser>(options =>
                    {
                        options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                    })
                    .AddEntityFrameworkStores<TestDbContext>();
                builder.Services.AddAccountManagementEndpoints();
            },
            app => app.MapGroup("/identity").MapAccountManagementEndpoints<TestAppUser>());
        var endpoint = ((IEndpointRouteBuilder)mapped).DataSources
            .SelectMany(source => source.Endpoints)
            .Single(item => item is RouteEndpoint route && route.RoutePattern.RawText == "/identity/manage/password");
        Assert.Contains(
            endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>(),
            data => data.Policy == "ReAuthPolicy");
        Assert.Contains(
            endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>(),
            data => data.AuthenticationSchemes?.Contains("Identity.Application", StringComparison.Ordinal) == true);
        Assert.NotNull(endpoint.Metadata.GetMetadata<AuthEndpointsAntiforgeryMetadata>());
        Assert.NotNull(endpoint.Metadata.GetMetadata<SetPasswordEndpointMetadata>());
        Assert.Equal(
            AuthEndpointsConstants.AccountAbusePolicy,
            endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName);

        var facade = RouteSurface.ListRoutes(RouteSurface.Build(
            builder =>
            {
                builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(options => options.Passkeys.Enabled = false);
                builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
            },
            app => app.MapAuthEndpoints<TestAppUser>()));
        Assert.DoesNotContain("POST /identity/manage/password", facade);

        using var defaults = RouteSurface.Build(
            builder => builder.Services.AddAccountManagementEndpoints(),
            _ => { });
        using var scope = defaults.Services.CreateScope();
        Assert.IsType<LoggingAccountSecurityEmailSender<TestAppUser>>(
            scope.ServiceProvider.GetRequiredService<IAccountSecurityEmailSender<TestAppUser>>());
    }

    [Fact]
    public async Task SetPassword_JwtManagementWithoutAccountManagementRegistration_SetsPassword()
    {
        await using var host = await JwtManagementHost.StartAsync();
        var email = Email();
        await host.SeedWithoutPasswordAsync(email);

        using (var scope = host.App.Services.CreateScope())
        {
            Assert.IsType<LoggingAccountSecurityEmailSender<TestAppUser>>(
                scope.ServiceProvider.GetRequiredService<IAccountSecurityEmailSender<TestAppUser>>());
        }

        var (accessToken, reauthToken) = await host.MintAsync(email);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/account/manage/password")
        {
            Content = JsonContent.Create(new { newPassword = "SetPass1!" }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation(AuthEndpointsConstants.ReAuthHeaderName, reauthToken);

        var response = await host.Client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode} {body}");
        Assert.True(await host.HasPasswordAsync(email));
    }

    [Fact]
    public async Task SetPassword_WrapsExistingAuthorizationResultHandler()
    {
        var custom = new StatusResultHandler();
        await using var host = await AuthorizationWrapHost.StartAsync(custom);

        var anonymous = await host.Client.PostAsJsonAsync("/identity/manage/password", new { newPassword = "SetPass1!" });
        Assert.Equal(HttpStatusCode.NotFound, anonymous.StatusCode);
        Assert.Equal(0, custom.Calls);

        var probe = await host.Client.GetAsync("/probe");
        Assert.Equal(StatusCodes.Status418ImATeapot, (int)probe.StatusCode);
        Assert.Equal(1, custom.Calls);
    }

    [Fact]
    public async Task LoggingSender_LogsStartupWarning()
    {
        var logs = new AuthEndpointsWarningLog();
        await using var app = await StartSenderHostAsync(logs, registerCustomSender: false);
        Assert.Contains(
            logs.Messages,
            message => message.Contains("LoggingAccountSecurityEmailSender", StringComparison.Ordinal)
                && message.Contains("does not send mail", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CustomSender_SkipsStartupWarning()
    {
        var logs = new AuthEndpointsWarningLog();
        await using var app = await StartSenderHostAsync(logs, registerCustomSender: true);
        Assert.DoesNotContain(
            logs.Messages,
            message => message.Contains("LoggingAccountSecurityEmailSender", StringComparison.Ordinal));
    }

    private static async Task<WebApplication> StartSenderHostAsync(AuthEndpointsWarningLog logs, bool registerCustomSender)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.WebHost.UseTestServer();
        builder.Logging.AddProvider(logs);
        if (registerCustomSender)
        {
            builder.Services.AddSingleton<IAccountSecurityEmailSender<TestAppUser>>(new CapturingEmailSender());
        }

        builder.Services.AddAccountManagementEndpoints();
        var app = builder.Build();
        await app.StartAsync();
        return app;
    }

    private static string Email() => $"set-password-{Guid.NewGuid():N}@test.local";

    private sealed class PasswordHost : IAsyncDisposable
    {
        private readonly string _path;

        private PasswordHost(WebApplication app, string path, CapturingEmailSender mail, bool mapPasswordSignIn)
        {
            App = app;
            _path = path;
            Mail = mail;
            Client = app.GetTestClient();
            MapPasswordSignIn = mapPasswordSignIn;
        }

        public WebApplication App { get; }

        public HttpClient Client { get; }

        public CapturingEmailSender Mail { get; }

        public bool MapPasswordSignIn { get; }

        public static async Task<PasswordHost> StartAsync(bool mapPasswordSignIn = true)
        {
            var path = Path.Combine(Path.GetTempPath(), $"ae-set-password-{Guid.NewGuid():N}.sqlite");
            var mail = new CapturingEmailSender();
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = Environments.Development,
            });
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<TestDbContext>(options =>
                options.UseSqlite($"Data Source={path};Default Timeout=30"));
            builder.Services.AddSingleton(mail);
            builder.Services.AddSingleton<IEmailSender<TestAppUser>>(mail);
            builder.Services.AddSingleton<IEmailCodeSender<TestAppUser>>(mail);
            builder.Services.AddSingleton<IAccountSecurityEmailSender<TestAppUser>>(mail);
            builder.Services
                .AddIdentityApiEndpoints<TestAppUser>(options =>
                {
                    options.SignIn.RequireConfirmedAccount = true;
                    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                    options.Password.RequireDigit = false;
                    options.Password.RequireLowercase = false;
                    options.Password.RequireUppercase = false;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequiredLength = 6;
                })
                .AddEntityFrameworkStores<TestDbContext>()
                .AddDefaultTokenProviders();
            builder.Services.Configure<SecurityStampValidatorOptions>(options =>
                options.ValidationInterval = TimeSpan.Zero);
            builder.Services.AddAuthorization();
            builder.Services.AddAntiforgery();
            if (mapPasswordSignIn)
            {
                builder.Services.AddPasswordSignInEndpoints();
            }

            builder.Services.AddCookieSessionEndpoints();
            builder.Services.AddBearerSessionEndpoints();
            builder.Services.AddAccountManagementEndpoints();
            builder.Services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>(options =>
            {
                options.ResendCooldown = TimeSpan.Zero;
                options.SendsPerIpPerMinute = 100;
            });

            var app = builder.Build();
            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                await db.Database.EnsureDeletedAsync();
                await db.Database.EnsureCreatedAsync();
            }

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseRateLimiter();
            app.UseAntiforgery();

            var identity = app.MapGroup("/identity");
            if (mapPasswordSignIn)
            {
                identity.MapPasswordSignInEndpoints<TestAppUser>();
            }

            identity.MapCookieSessionEndpoints<TestAppUser>();
            identity.MapAccountManagementEndpoints<TestAppUser>();
            identity.MapEmailCodeSendEndpoints<TestAppUser>();
            identity.MapEmailCodeSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);

            var mobile = app.MapGroup("/mobile");
            mobile.MapEmailCodeSignInEndpoints<TestAppUser>(AuthEndpointsSession.IdentityBearer);
            mobile.MapBearerSessionEndpoints<TestAppUser>();

            await app.StartAsync();
            return new PasswordHost(app, path, mail, mapPasswordSignIn);
        }

        public async Task SeedWithoutPasswordAsync(string email)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = new TestAppUser { UserName = email, Email = email, EmailConfirmed = true };
            var created = await users.CreateAsync(user);
            Assert.True(created.Succeeded, string.Join("; ", created.Errors.Select(error => error.Description)));
        }

        public async Task SeedWithPasswordAsync(string email, string password)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = new TestAppUser { UserName = email, Email = email, EmailConfirmed = true };
            var created = await users.CreateAsync(user, password);
            Assert.True(created.Succeeded, string.Join("; ", created.Errors.Select(error => error.Description)));
        }

        public async Task<bool> HasPasswordAsync(string email)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = await users.FindByEmailAsync(email);
            return user is not null && await users.HasPasswordAsync(user);
        }

        public async Task<string> StampAsync(string email)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = await users.FindByEmailAsync(email);
            return await users.GetSecurityStampAsync(user!);
        }

        public async Task<CookieJar> SignInCookieAsync(string email)
        {
            var code = await SendSignInCodeAsync(email);
            var jar = new CookieJar();
            var response = await PostAsync(
                jar,
                "/identity/emailCode/verify?useSessionCookies=true",
                new { email, code },
                csrf: false);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await GetAsync(jar, "/identity/manage/info")).StatusCode);
            return jar;
        }

        public async Task<CookieJar> SignInPasswordAsync(string email, string password)
        {
            var jar = new CookieJar();
            var response = await PostAsync(jar, "/identity/login", new { email, password }, csrf: false);
            Assert.True(
                response.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
                await response.Content.ReadAsStringAsync());
            return jar;
        }

        public async Task<(string AccessToken, string RefreshToken)> SignInBearerAsync(string email)
        {
            var code = await SendSignInCodeAsync(email);
            var response = await Client.PostAsJsonAsync("/mobile/emailCode/verify", new { email, code });
            var body = await response.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var doc = JsonDocument.Parse(body);
            var access = TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken");
            var refresh = TestHelpers.TryGetString(doc.RootElement, "refreshToken", "RefreshToken");
            Assert.False(string.IsNullOrWhiteSpace(access));
            Assert.False(string.IsNullOrWhiteSpace(refresh));
            return (access!, refresh!);
        }

        public async Task ConfirmEmailCodeAsync(CookieJar jar, string email)
        {
            var sent = await PostAsync(jar, "/identity/confirmIdentity/emailCode/send", new { }, csrf: true);
            Assert.Equal(HttpStatusCode.OK, sent.StatusCode);
            var code = Mail.Snapshot().Last(item => item.Email == email && item.Purpose == EmailCodePurpose.ReAuth).Body;
            var confirmed = await PostAsync(jar, "/identity/confirmIdentity", new { emailCode = code }, csrf: true);
            Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        }

        public async Task ConfirmPasswordAsync(CookieJar jar, string password)
        {
            var confirmed = await PostAsync(jar, "/identity/confirmIdentity", new { password }, csrf: true);
            Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        }

        public async Task<HttpResponseMessage> GetAsync(CookieJar jar, string url)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            jar.Apply(request, Client.BaseAddress!);
            var response = await Client.SendAsync(request);
            jar.Capture(response, Client.BaseAddress!);
            return response;
        }

        public async Task<HttpResponseMessage> PostAsync(CookieJar jar, string url, object body, bool csrf)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = JsonContent.Create(body),
            };
            if (csrf)
            {
                request.Headers.TryAddWithoutValidation("RequestVerificationToken", await CsrfAsync(jar));
            }

            if (Client.BaseAddress is not null)
            {
                request.Headers.TryAddWithoutValidation("Origin", Client.BaseAddress.GetLeftPart(UriPartial.Authority));
            }

            jar.Apply(request, Client.BaseAddress!);
            var response = await Client.SendAsync(request);
            jar.Capture(response, Client.BaseAddress!);
            return response;
        }

        private async Task<string> SendSignInCodeAsync(string email)
        {
            var sent = await Client.PostAsJsonAsync("/identity/emailCode/send", new { email });
            Assert.Equal(HttpStatusCode.OK, sent.StatusCode);
            return Mail.Snapshot().Last(item => item.Email == email && item.Purpose == EmailCodePurpose.SignIn).Body;
        }

        private async Task<string> CsrfAsync(CookieJar jar)
        {
            var response = await GetAsync(jar, "/identity/csrfToken");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (doc.RootElement.TryGetProperty("csrfToken", out var camel))
            {
                return camel.GetString()!;
            }

            return doc.RootElement.GetProperty("CsrfToken").GetString()!;
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await App.StopAsync();
            await App.DisposeAsync();
            SqliteConnection.ClearAllPools();
            TryDelete(_path);
            TryDelete(_path + "-wal");
            TryDelete(_path + "-shm");
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (IOException)
            {
            }
        }
    }

    private sealed class CookieJar
    {
        private readonly System.Net.CookieContainer _cookies = new();

        public void Capture(HttpResponseMessage response, Uri baseAddress)
        {
            if (!response.Headers.TryGetValues("Set-Cookie", out var values))
            {
                return;
            }

            foreach (var value in values)
            {
                _cookies.SetCookies(baseAddress, value);
            }
        }

        public void Apply(HttpRequestMessage request, Uri baseAddress)
        {
            var header = _cookies.GetCookieHeader(baseAddress);
            if (!string.IsNullOrEmpty(header))
            {
                request.Headers.TryAddWithoutValidation("Cookie", header);
            }
        }
    }

    private sealed class JwtManagementHost : IAsyncDisposable
    {
        private readonly string _path;

        private JwtManagementHost(WebApplication app, string path)
        {
            App = app;
            _path = path;
            Client = app.GetTestClient();
        }

        public WebApplication App { get; }

        public HttpClient Client { get; }

        public static async Task<JwtManagementHost> StartAsync()
        {
            var path = Path.Combine(Path.GetTempPath(), $"ae-set-password-jwt-{Guid.NewGuid():N}.sqlite");
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = Environments.Development,
            });
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<TestDbContext>(options =>
                options.UseSqlite($"Data Source={path};Default Timeout=30"));
            builder.Services
                .AddIdentityApiEndpoints<TestAppUser>(options =>
                {
                    options.SignIn.RequireConfirmedAccount = false;
                    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                })
                .AddEntityFrameworkStores<TestDbContext>()
                .AddDefaultTokenProviders();
            builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(options =>
            {
                options.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            });
            builder.Services.AddReAuthScheme();
            builder.Services.AddAntiforgery();

            var app = builder.Build();
            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                await db.Database.EnsureCreatedAsync();
            }

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseRateLimiter();
            app.UseAntiforgery();
            app.MapGroup("/account").MapIdentityManagementApi<TestAppUser>();
            app.MapGroup("/auth").MapJwtPasswordEndpoints<TestAppUser>();
            await app.StartAsync();
            return new JwtManagementHost(app, path);
        }

        public async Task SeedWithoutPasswordAsync(string email)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = new TestAppUser { UserName = email, Email = email, EmailConfirmed = true };
            var created = await users.CreateAsync(user);
            Assert.True(created.Succeeded, string.Join("; ", created.Errors.Select(error => error.Description)));
        }

        public async Task<bool> HasPasswordAsync(string email)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = await users.FindByEmailAsync(email);
            return user is not null && await users.HasPasswordAsync(user);
        }

        public async Task<(string AccessToken, string ReauthToken)> MintAsync(string email)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var signIn = scope.ServiceProvider.GetRequiredService<SignInManager<TestAppUser>>();
            var user = await users.FindByEmailAsync(email);
            Assert.NotNull(user);
            var principal = await signIn.CreateUserPrincipalAsync(user);
            var accessToken = scope.ServiceProvider.GetRequiredService<IAccessTokenGenerator>().GenerateAccessToken(principal);
            var stampType = users.Options.ClaimsIdentity.SecurityStampClaimType;
            var claims = principal.Claims
                .Where(claim => !string.Equals(claim.Type, stampType, StringComparison.Ordinal)
                    && !string.Equals(claim.Type, "Reauth", StringComparison.Ordinal)
                    && !string.Equals(claim.Type, "ReauthTime", StringComparison.Ordinal))
                .ToList();
            claims.Add(new Claim("Reauth", "true"));
            claims.Add(new Claim(stampType, await users.GetSecurityStampAsync(user)));
            var reauthToken = scope.ServiceProvider.GetRequiredService<ReAuthTokenService>().CreateToken(claims);
            return (accessToken, reauthToken);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await App.StopAsync();
            await App.DisposeAsync();
            SqliteConnection.ClearAllPools();
            TryDelete(_path);
            TryDelete(_path + "-wal");
            TryDelete(_path + "-shm");
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (IOException)
            {
            }
        }
    }

    private sealed class AuthorizationWrapHost : IAsyncDisposable
    {
        private AuthorizationWrapHost(WebApplication app)
        {
            Client = app.GetTestClient();
            App = app;
        }

        public WebApplication App { get; }

        public HttpClient Client { get; }

        public static async Task<AuthorizationWrapHost> StartAsync(StatusResultHandler custom)
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = Environments.Development,
            });
            builder.WebHost.UseTestServer();
            builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler>(custom);
            builder.Services.AddDbContext<TestDbContext>(options =>
                options.UseInMemoryDatabase($"set-password-wrap-{Guid.NewGuid():N}"));
            builder.Services
                .AddIdentityApiEndpoints<TestAppUser>(options =>
                {
                    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                })
                .AddEntityFrameworkStores<TestDbContext>();
            builder.Services.AddAccountManagementEndpoints();

            var app = builder.Build();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapGroup("/identity").MapAccountManagementEndpoints<TestAppUser>();
            app.MapGet("/probe", () => Results.Ok()).RequireAuthorization();
            await app.StartAsync();
            return new AuthorizationWrapHost(app);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await App.StopAsync();
            await App.DisposeAsync();
        }
    }

    private sealed class StatusResultHandler : IAuthorizationMiddlewareResultHandler
    {
        public int Calls { get; private set; }

        public Task HandleAsync(
            RequestDelegate next,
            HttpContext context,
            AuthorizationPolicy policy,
            PolicyAuthorizationResult authorizeResult)
        {
            Calls++;
            context.Response.StatusCode = StatusCodes.Status418ImATeapot;
            return Task.CompletedTask;
        }
    }

    private sealed class AuthEndpointsWarningLog : ILoggerProvider
    {
        public List<string> Messages { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Logger(categoryName, Messages);

        public void Dispose()
        {
        }

        private sealed class Logger(string category, List<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) =>
                logLevel >= LogLevel.Warning && category == AuthEndpointsModules.LogCategory;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (!IsEnabled(logLevel))
                {
                    return;
                }

                messages.Add(formatter(state, exception));
            }
        }
    }
}
