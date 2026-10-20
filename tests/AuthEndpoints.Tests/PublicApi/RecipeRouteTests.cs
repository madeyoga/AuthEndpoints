using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints;
using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Tests.PublicApi;

public class RecipeRouteTests
{
    [Fact]
    public void EmailCodeOnly_MapsSessionAndAccountRoutes_AndOmitsPasswordSignIn()
    {
        var routes = Map(services =>
        {
            services.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>(options =>
            {
                options.User.RequireUniqueEmail = true;
            });
            services.AddCookieSessionEndpoints();
            services.AddAccountManagementEndpoints();
            services.AddSingleton<IEmailCodeSender<TestAppUser>>(new CapturingEmailSender());
            services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>(options => options.AllowSignUp = true);
        }, app =>
        {
            var auth = app.MapGroup("/auth");
            auth.MapEmailCodeEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
            auth.MapCookieSessionEndpoints<TestAppUser>();
            auth.MapAccountManagementEndpoints<TestAppUser>();
        });

        Assert.Equal(
            [
                "GET /auth/confirmEmail",
                "GET /auth/csrfToken",
                "GET /auth/manage/2fa",
                "GET /auth/manage/authMethods",
                "GET /auth/manage/info",
                "POST /auth/confirmIdentity",
                "POST /auth/confirmIdentity/emailCode/send",
                "POST /auth/emailCode/send",
                "POST /auth/emailCode/verify",
                "POST /auth/logout",
                "POST /auth/manage/2fa",
                "POST /auth/manage/info",
                "POST /auth/manage/password",
                "POST /auth/resendConfirmationEmail",
            ],
            routes);
    }

    [Fact]
    public async Task EmailCodeOnly_SendVerifyInfoStepUpLogout_AndLogsNoMissingAddWarning()
    {
        var logs = new WarningLog();
        await using var host = await EmailCodeOnlyHost.StartAsync(logs);
        var email = $"recipe-{Guid.NewGuid():N}@test.local";
        var jar = new CookieJar();

        var send = await PostAsync(host.Client, "/auth/emailCode/send", new { email }, jar);
        Assert.Equal(HttpStatusCode.OK, send.StatusCode);

        var code = host.Mail.Snapshot().Single(item => item.Kind == "email-code" && item.Email == email).Body;
        var verify = await PostAsync(
            host.Client,
            "/auth/emailCode/verify?useCookies=true",
            new { email, code },
            jar);
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);

        var info = await GetAsync(host.Client, "/auth/manage/info", jar);
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);

        var csrf = await GetAsync(host.Client, "/auth/csrfToken", jar);
        Assert.Equal(HttpStatusCode.OK, csrf.StatusCode);
        var token = ReadCsrf(await csrf.Content.ReadAsStringAsync());
        var stepUp = await PostAsync(
            host.Client,
            "/auth/manage/info",
            new { newEmail = email },
            jar,
            token);
        Assert.Equal(HttpStatusCode.Forbidden, stepUp.StatusCode);

        Assert.Equal(HttpStatusCode.NotFound, (await PostAsync(host.Client, "/auth/register", new { email, password = "Passw0rd!" }, jar)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await PostAsync(host.Client, "/auth/login", new { email, password = "Passw0rd!" }, jar)).StatusCode);

        var logout = await PostAsync(host.Client, "/auth/logout", new { }, jar, token);
        Assert.True(
            logout.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
            $"Logout failed: {(int)logout.StatusCode} {await logout.Content.ReadAsStringAsync()}");

        var signedOut = await GetAsync(host.Client, "/auth/manage/info", jar);
        Assert.Equal(HttpStatusCode.Unauthorized, signedOut.StatusCode);
        Assert.DoesNotContain(logs.Messages, message => message.Contains("was not called before", StringComparison.Ordinal));
    }

    [Fact]
    public void BearerCompose_MatchesFacadeRouteList()
    {
        var routes = Map(services =>
        {
            services
                .AddIdentityApiEndpoints<TestAppUser>(options =>
                {
                    options.SignIn.RequireConfirmedAccount = true;
                    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                })
                .AddEntityFrameworkStores<TestDbContext>()
                .AddDefaultTokenProviders();
            services.AddBearerAuthEndpoints();
            services.AddPasskeyEndpoints<TestAppUser>();
        }, app =>
        {
            var auth = app.MapGroup("/auth");
            auth.MapIdentityManagementApi<TestAppUser>();
            auth.MapBearerAuthEndpoints<TestAppUser>();
            auth.MapPasskeyEndpoints<TestAppUser>();
        });

        Assert.Equal(WithSetPassword(BearerFacadeRoutes), routes);
    }

    [Fact]
    public void JwtOnly_MapsManagementAndJwtOnAuthPrefix()
    {
        var routes = Map(services =>
        {
            services
                .AddIdentityApiEndpoints<TestAppUser>(options =>
                {
                    options.SignIn.RequireConfirmedAccount = true;
                    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                })
                .AddEntityFrameworkStores<TestDbContext>()
                .AddDefaultTokenProviders();
            services.AddPasswordEndpoints();
            services.AddAccountManagementEndpoints();
            services.AddAntiforgery();
            services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            });
        }, app =>
        {
            var auth = app.MapGroup("/auth");
            auth.MapIdentityManagementApi<TestAppUser>();
            auth.MapJwtAuthEndpoints<TestAppUser>();
        });

        Assert.Equal(
            [
                "GET /auth/confirmEmail",
                "GET /auth/csrfToken",
                "GET /auth/manage/2fa",
                "GET /auth/manage/authMethods",
                "GET /auth/manage/info",
                "GET /auth/verify",
                "POST /auth/confirmIdentity",
                "POST /auth/confirmIdentity/passkeyOptions",
                "POST /auth/create",
                "POST /auth/forgotPassword",
                "POST /auth/logout",
                "POST /auth/manage/2fa",
                "POST /auth/manage/info",
                "POST /auth/manage/password",
                "POST /auth/refresh",
                "POST /auth/register",
                "POST /auth/resendConfirmationEmail",
                "POST /auth/resetPassword",
            ],
            routes);
    }

    [Fact]
    public void CustomPrefix_MapsLoginUnderThatPrefix()
    {
        var routes = Map(services => services.AddCookieAuthEndpoints(), app =>
        {
            app.MapGroup("/api/account").MapCookieAuthEndpoints<TestAppUser>();
        });

        Assert.Contains("POST /api/account/login", routes);
        Assert.DoesNotContain("POST /identity/login", routes);
    }

    private static IReadOnlyList<string> Map(Action<IServiceCollection> configure, Action<WebApplication> map)
    {
        using var app = RouteSurface.Build(builder => configure(builder.Services), map);
        return RouteSurface.ListRoutes(app);
    }

    private static async Task<HttpResponseMessage> PostAsync(
        HttpClient client,
        string url,
        object body,
        CookieJar cookies,
        string? csrf = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(body)
        };
        if (!string.IsNullOrEmpty(csrf))
        {
            request.Headers.TryAddWithoutValidation("RequestVerificationToken", csrf);
        }

        cookies.Apply(request, client.BaseAddress!);
        var response = await client.SendAsync(request);
        cookies.Capture(response, client.BaseAddress!);
        return response;
    }

    private static async Task<HttpResponseMessage> GetAsync(HttpClient client, string url, CookieJar cookies)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        cookies.Apply(request, client.BaseAddress!);
        var response = await client.SendAsync(request);
        cookies.Capture(response, client.BaseAddress!);
        return response;
    }

    private static string ReadCsrf(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("csrfToken", out var camel))
        {
            return camel.GetString()!;
        }

        return doc.RootElement.GetProperty("CsrfToken").GetString()!;
    }

    private static string[] WithSetPassword(IReadOnlyList<string> routes)
    {
        return routes
            .Append("POST /auth/manage/password")
            .OrderBy(route => route, StringComparer.Ordinal)
            .ToArray();
    }

    private static readonly string[] BearerFacadeRoutes =
    [
        "DELETE /auth/passkeys/{credentialIdUrl}",
        "GET /auth/confirmEmail",
        "GET /auth/manage/2fa",
        "GET /auth/manage/authMethods",
        "GET /auth/manage/info",
        "GET /auth/passkeys/",
        "PATCH /auth/passkeys/",
        "POST /auth/confirmIdentity",
        "POST /auth/confirmIdentity/passkeyOptions",
        "POST /auth/forgotPassword",
        "POST /auth/login",
        "POST /auth/logout",
        "POST /auth/manage/2fa",
        "POST /auth/manage/info",
        "POST /auth/passkeys/",
        "POST /auth/passkeys/creationOptions",
        "POST /auth/passkeys/login",
        "POST /auth/passkeys/register",
        "POST /auth/passkeys/register/options",
        "POST /auth/passkeys/requestOptions",
        "POST /auth/refresh",
        "POST /auth/register",
        "POST /auth/resendConfirmationEmail",
        "POST /auth/resetPassword",
    ];

    private sealed class EmailCodeOnlyHost : IAsyncDisposable
    {
        private readonly string _path;

        private EmailCodeOnlyHost(WebApplication app, string path, CapturingEmailSender mail)
        {
            App = app;
            _path = path;
            Mail = mail;
            Client = app.GetTestClient();
        }

        public WebApplication App { get; }

        public HttpClient Client { get; }

        public CapturingEmailSender Mail { get; }

        public static async Task<EmailCodeOnlyHost> StartAsync(WarningLog logs)
        {
            var path = Path.Combine(Path.GetTempPath(), $"ae-email-code-recipe-{Guid.NewGuid():N}.sqlite");
            var mail = new CapturingEmailSender();
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = Environments.Development,
            });
            builder.WebHost.UseTestServer();
            builder.Logging.AddProvider(logs);
            builder.Logging.SetMinimumLevel(LogLevel.Warning);
            builder.Services.AddDbContext<TestDbContext>(options =>
                options.UseSqlite($"Data Source={path};Default Timeout=30"));
            builder.Services.AddSingleton(mail);
            builder.Services.AddSingleton<IEmailSender<TestAppUser>>(mail);
            builder.Services.AddSingleton<IEmailCodeSender<TestAppUser>>(mail);
            builder.Services.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>(options =>
            {
                options.User.RequireUniqueEmail = true;
            });
            builder.Services.AddCookieSessionEndpoints();
            builder.Services.AddAccountManagementEndpoints();
            builder.Services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>(options => options.AllowSignUp = true);

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
            var auth = app.MapGroup("/auth");
            auth.MapEmailCodeEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
            auth.MapCookieSessionEndpoints<TestAppUser>();
            auth.MapAccountManagementEndpoints<TestAppUser>();
            await app.StartAsync();
            return new EmailCodeOnlyHost(app, path, mail);
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

    private sealed class WarningLog : ILoggerProvider
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
