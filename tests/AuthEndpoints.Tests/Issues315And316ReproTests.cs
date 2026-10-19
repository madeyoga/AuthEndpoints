using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Tests;

/// <summary>
/// Reproductions for issues 315 and 316. They observe the password facade; they do not change it.
/// Issue 315: https://github.com/madeyoga/AuthEndpoints/issues/315
/// Issue 316: https://github.com/madeyoga/AuthEndpoints/issues/316
/// </summary>
public sealed class Issues315And316ReproTests
{
    private const string SigningKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";

    [Fact(Skip = "Issue #315: GET /auth/csrfToken is 404. POST /auth/passkeys/requestOptions, /register/options, /register, and /login return 400 \"Invalid or missing CSRF token.\"")]
    public async Task Issue315_WithoutHostAntiforgeryEndpoint_ClientCompletesPasskeyCeremony()
    {
        var report = await RunPasskeyCeremonyAsync(mapHostAntiforgeryEndpoint: false);
        Assert.True(report.Completed, report.Detail);
    }

    [Fact]
    public async Task Issue315_WithHostAntiforgeryEndpoint_ClientCompletesPasskeyCeremony()
    {
        var report = await RunPasskeyCeremonyAsync(mapHostAntiforgeryEndpoint: true);
        Assert.True(report.Completed, report.Detail);
    }

    [Fact(Skip = "Issue #316: with Passkeys.ServerDomain set, MapCookieAuthEndpoints and MapIdentityManagementApi do not throw. Duplicate routes return 500 AmbiguousMatchException.")]
    public async Task Issue316_WithServerDomain_ExtraMapsThrowMissingAdd()
    {
        var cookie = await ProbeExtraMapAsync("localhost", ExtraMap.CookieAuth);
        var management = await ProbeExtraMapAsync("localhost", ExtraMap.IdentityManagement);
        Assert.True(
            cookie.GuardThrew && management.GuardThrew,
            cookie.Summary + Environment.NewLine + Environment.NewLine + management.Summary);
    }

    [Fact]
    public async Task Issue316_WithoutServerDomain_ExtraMapsThrowMissingAdd()
    {
        var cookie = await ProbeExtraMapAsync(serverDomain: null, ExtraMap.CookieAuth);
        var management = await ProbeExtraMapAsync(serverDomain: null, ExtraMap.IdentityManagement);
        Assert.True(
            cookie.GuardThrew && management.GuardThrew,
            cookie.Summary + Environment.NewLine + Environment.NewLine + management.Summary);
    }

    private static async Task<CeremonyReport> RunPasskeyCeremonyAsync(bool mapHostAntiforgeryEndpoint)
    {
        var mail = new CapturingEmailSender();
        var databasePath = Path.Combine(Path.GetTempPath(), $"ae-repro-315-{Guid.NewGuid():N}.sqlite");
        var detail = new StringBuilder();
        detail.AppendLine("host: AddPasswordAuth Session=Jwt RefreshTokenTransport.Body Passkeys.ServerDomain=localhost RequireConfirmedAccount=true");
        detail.AppendLine("host-mapped antiforgery endpoint: " + (mapHostAntiforgeryEndpoint ? "GET /auth/csrfToken" : "none"));

        var app = await StartCeremonyHostAsync(mail, databasePath, mapHostAntiforgeryEndpoint);
        await using var _ = app;
        var http = app.GetTestServer().CreateClient();
        var cookies = new CookieContainer();
        var origin = http.BaseAddress!.GetLeftPart(UriPartial.Authority);
        var email = $"repro-315-{Guid.NewGuid():N}@test.local";
        var authenticator = new SoftwareWebAuthnAuthenticator();
        detail.AppendLine("origin: " + origin);

        var libraryCsrf = await SendAsync(http, cookies, HttpMethod.Get, "/auth/csrfToken", body: null, csrfToken: null);
        detail.AppendLine(libraryCsrf.Line);
        var csrfAvailable = libraryCsrf.Status == HttpStatusCode.OK;

        var requestOptions = await PostCeremonyAsync(http, cookies, "/auth/passkeys/requestOptions", new { email }, csrfAvailable);
        detail.AppendLine(requestOptions.Line);

        var registerOptions = await PostCeremonyAsync(http, cookies, "/auth/passkeys/register/options", new { email }, csrfAvailable);
        detail.AppendLine(registerOptions.Line);

        string credentialJson;
        if (registerOptions.Status == HttpStatusCode.OK)
        {
            try
            {
                credentialJson = authenticator.CreateAttestation(registerOptions.Body, origin);
                detail.AppendLine("attestation: produced credentialJson");
            }
            catch (Exception ex)
            {
                credentialJson = "{}";
                detail.AppendLine($"attestation: {ex.GetType().Name}: {ex.Message}");
            }
        }
        else
        {
            credentialJson = "{}";
            detail.AppendLine("attestation: skipped");
        }

        var register = await PostCeremonyAsync(
            http,
            cookies,
            "/auth/passkeys/register",
            new { email, credentialJson },
            csrfAvailable);
        detail.AppendLine(register.Line);

        Exchange? confirm = null;
        var confirmMail = mail.Snapshot().FirstOrDefault(item => item.Email == email && item.Kind == "confirm");
        if (confirmMail is not null)
        {
            var confirmPath = new Uri(System.Net.WebUtility.HtmlDecode(confirmMail.Body)).PathAndQuery;
            confirm = await SendAsync(http, cookies, HttpMethod.Get, confirmPath, body: null, csrfToken: null);
            detail.AppendLine("GET confirmEmail " + confirm.Line);
        }
        else
        {
            detail.AppendLine("confirmEmail: no confirmation mail");
        }

        var loginOptions = await PostCeremonyAsync(http, cookies, "/auth/passkeys/requestOptions", new { email }, csrfAvailable);
        detail.AppendLine("login " + loginOptions.Line);

        string assertionJson;
        if (loginOptions.Status == HttpStatusCode.OK)
        {
            try
            {
                assertionJson = authenticator.CreateAssertion(loginOptions.Body, origin);
                detail.AppendLine("assertion: produced credentialJson");
            }
            catch (Exception ex)
            {
                assertionJson = "{}";
                detail.AppendLine($"assertion: {ex.GetType().Name}: {ex.Message}");
            }
        }
        else
        {
            assertionJson = "{}";
            detail.AppendLine("assertion: skipped");
        }

        var login = await PostCeremonyAsync(
            http,
            cookies,
            "/auth/passkeys/login",
            new { credentialJson = assertionJson },
            csrfAvailable);
        detail.AppendLine(login.Line);

        string? accessToken = null;
        string? refreshToken = null;
        if (login.Status == HttpStatusCode.OK && login.Body.Length > 0 && login.Body.TrimStart().StartsWith('{'))
        {
            using var loginDoc = JsonDocument.Parse(login.Body);
            accessToken = TestHelpers.TryGetString(loginDoc.RootElement, "accessToken", "AccessToken");
            refreshToken = TestHelpers.TryGetString(loginDoc.RootElement, "refreshToken", "RefreshToken");
        }

        detail.AppendLine("login accessToken: " + (string.IsNullOrWhiteSpace(accessToken) ? "absent" : "present"));
        detail.AppendLine("login refreshToken: " + (string.IsNullOrWhiteSpace(refreshToken) ? "absent" : "present"));
        detail.AppendLine("login refresh cookie: " + (login.SetCookie.Contains("AuthEndpoints.Jwt.RefreshToken", StringComparison.Ordinal) ? "set" : "absent"));

        Exchange? verify = null;
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            verify = await SendAsync(
                http,
                cookies,
                HttpMethod.Get,
                "/auth/verify",
                body: null,
                csrfToken: null,
                bearer: accessToken);
            detail.AppendLine(verify.Line);
        }
        else
        {
            detail.AppendLine("GET /auth/verify: skipped");
        }

        var csrfMatchesScenario = mapHostAntiforgeryEndpoint
            ? libraryCsrf.Status == HttpStatusCode.OK
            : libraryCsrf.Status == HttpStatusCode.NotFound;
        var completed = csrfMatchesScenario
            && requestOptions.Status == HttpStatusCode.OK
            && registerOptions.Status == HttpStatusCode.OK
            && register.Status == HttpStatusCode.OK
            && confirm?.Status == HttpStatusCode.OK
            && loginOptions.Status == HttpStatusCode.OK
            && login.Status == HttpStatusCode.OK
            && !string.IsNullOrWhiteSpace(accessToken)
            && !string.IsNullOrWhiteSpace(refreshToken)
            && !login.SetCookie.Contains("AuthEndpoints.Jwt.RefreshToken", StringComparison.Ordinal)
            && verify?.Status == HttpStatusCode.NoContent;

        return new CeremonyReport(completed, detail.ToString());
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
        }

        return await SendAsync(http, cookies, HttpMethod.Post, path, body, csrfToken);
    }

    private static async Task<WebApplication> StartCeremonyHostAsync(
        CapturingEmailSender mail,
        string databasePath,
        bool mapHostAntiforgeryEndpoint)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(o => o.UseSqlite($"Data Source={databasePath}"));
        builder.Services.AddSingleton(mail);
        builder.Services.AddSingleton<IEmailSender<TestAppUser>>(mail);
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(o =>
        {
            o.Session = AuthEndpointsSession.Jwt;
            o.RequireConfirmedAccount = true;
            o.Passkeys.ServerDomain = "localhost";
            o.Jwt = jwt =>
            {
                jwt.SigningOptions.SymmetricKey = SigningKey;
                jwt.RefreshTokenTransport = RefreshTokenTransport.Body;
            };
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

    private static async Task<ProbeResult> ProbeExtraMapAsync(string? serverDomain, ExtraMap extraMap)
    {
        var expectedMessage = extraMap == ExtraMap.CookieAuth
            ? "Call AddPasswordEndpoints before MapCookieAuthEndpoints."
            : "Call AddPasswordEndpoints before MapPasswordEndpoints.";
        var logs = new WarningLog();
        var summary = new StringBuilder();
        summary.AppendLine("host: AddPasswordAuth Session=Jwt RefreshTokenTransport.Body");
        summary.AppendLine("Passkeys.ServerDomain: " + (serverDomain ?? "(unset)"));
        summary.AppendLine("extra map: " + extraMap);

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.WebHost.UseTestServer();
        builder.Logging.AddProvider(logs);
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Services.AddDbContext<TestDbContext>(o =>
            o.UseInMemoryDatabase("repro-316-" + Guid.NewGuid().ToString("N")));
        builder.Services.AddSingleton<IEmailSender<TestAppUser>, TestEmailSender>();
        builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(o =>
        {
            o.Session = AuthEndpointsSession.Jwt;
            o.Passkeys.ServerDomain = serverDomain;
            o.Jwt = jwt =>
            {
                jwt.SigningOptions.SymmetricKey = SigningKey;
                jwt.RefreshTokenTransport = RefreshTokenTransport.Body;
            };
        });

        await using var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            await db.Database.EnsureCreatedAsync();
        }

        app.UseAuthEndpoints();
        var passwordMap = Record.Exception(() => app.MapPasswordAuth<TestAppUser>());
        summary.AppendLine("MapPasswordAuth: " + FormatException(passwordMap));

        Exception? extra = null;
        if (passwordMap is null)
        {
            extra = Record.Exception(() =>
            {
                var group = app.MapGroup("/auth");
                if (extraMap == ExtraMap.CookieAuth)
                {
                    group.MapCookieAuthEndpoints<TestAppUser>();
                }
                else
                {
                    group.MapIdentityManagementApi<TestAppUser>();
                }
            });
        }

        summary.AppendLine("extra map result: " + FormatException(extra));
        summary.AppendLine("expected guard: " + expectedMessage);

        Exception? listed = null;
        if (passwordMap is null && extra is null)
        {
            listed = Record.Exception(() =>
            {
                foreach (var line in RouteLines(app))
                {
                    summary.AppendLine("route: " + line);
                }
            });
            if (listed is not null)
            {
                summary.AppendLine("route list: " + FormatException(listed));
            }
        }

        summary.AppendLine("warnings: " + (logs.Messages.Count == 0 ? "(none)" : string.Join(" | ", logs.Messages)));

        if (passwordMap is null && extra is null && listed is null)
        {
            Exception? started = null;
            try
            {
                await app.StartAsync();
            }
            catch (Exception ex)
            {
                started = ex;
            }

            summary.AppendLine("StartAsync: " + FormatException(started));
            if (started is null)
            {
                var http = app.GetTestServer().CreateClient();
                if (extraMap == ExtraMap.CookieAuth)
                {
                    await AppendProbeAsync(summary, http, HttpMethod.Get, "/auth/csrfToken", body: null);
                    await AppendProbeAsync(summary, http, HttpMethod.Post, "/auth/login", new { email = "nobody@test.local", password = TestHelpers.DefaultPassword });
                    await AppendProbeAsync(summary, http, HttpMethod.Post, "/auth/logout", new { });
                }
                else
                {
                    await AppendProbeAsync(
                        summary,
                        http,
                        HttpMethod.Post,
                        "/auth/register",
                        new { email = $"repro-316-{Guid.NewGuid():N}@test.local", password = TestHelpers.DefaultPassword });
                    await AppendProbeAsync(summary, http, HttpMethod.Get, "/auth/manage/info", body: null);
                }
            }
        }
        else
        {
            summary.AppendLine("StartAsync: skipped");
        }

        var guardThrew = extra is InvalidOperationException && extra.Message == expectedMessage;
        return new ProbeResult(guardThrew, summary.ToString());
    }

    private static async Task AppendProbeAsync(StringBuilder summary, HttpClient http, HttpMethod method, string path, object? body)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        using var response = await http.SendAsync(request);
        var responseBody = Trim(await response.Content.ReadAsStringAsync());
        summary.AppendLine($"{method} {path} -> {(int)response.StatusCode} {response.StatusCode} {responseBody}");
    }

    private static IEnumerable<string> RouteLines(WebApplication app)
    {
        return ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>()
            .Select(endpoint =>
            {
                var methods = endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods;
                var method = methods is { Count: > 0 } ? string.Join(',', methods) : "*";
                var path = endpoint.RoutePattern.RawText ?? endpoint.RoutePattern.ToString();
                return method + " " + path;
            })
            .Where(line =>
                line.Contains("csrfToken", StringComparison.Ordinal)
                || line.Contains("/login", StringComparison.Ordinal)
                || line.Contains("/logout", StringComparison.Ordinal)
                || line.Contains("/register", StringComparison.Ordinal)
                || line.Contains("/manage/", StringComparison.Ordinal)
                || line.Contains("/passkeys/", StringComparison.Ordinal))
            .GroupBy(line => line, StringComparer.Ordinal)
            .Select(group => group.Key + " x" + group.Count())
            .OrderBy(line => line, StringComparer.Ordinal);
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

        if (!message.Headers.Contains("Origin"))
        {
            message.Headers.TryAddWithoutValidation("Origin", http.BaseAddress!.GetLeftPart(UriPartial.Authority));
        }

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
        return new Exchange(method, path, csrfToken is not null, response.StatusCode, responseBody, setCookie);
    }

    private static string? ReadCsrfToken(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return TestHelpers.TryGetString(doc.RootElement, "csrfToken", "CsrfToken");
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string FormatException(Exception? exception) =>
        exception is null ? "no exception" : exception.GetType().Name + ": " + exception.Message;

    private static string Trim(string body)
    {
        var flat = body.Replace("\r", "", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
        return flat.Length <= 400 ? flat : flat[..400] + "…";
    }

    private enum ExtraMap
    {
        CookieAuth,
        IdentityManagement,
    }

    private sealed record CeremonyReport(bool Completed, string Detail);

    private sealed record ProbeResult(bool GuardThrew, string Summary);

    private sealed record Exchange(HttpMethod Method, string Path, bool SentCsrf, HttpStatusCode Status, string Body, string SetCookie)
    {
        public string Line =>
            $"{Method} {Path} csrf={(SentCsrf ? "sent" : "absent")} -> {(int)Status} {Status} {Trim(Body)}";
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
