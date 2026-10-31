using System.Diagnostics;
using Xunit.Abstractions;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.Tests;

public sealed class EnumerationResponseTests : IAsyncLifetime
{
    /// <summary>
    /// Median absolute difference allowed between a known-account request and an unknown-account request
    /// after one warmed pair. The test sender does not perform network I/O.
    /// Hosts should queue mail and return; inline SMTP is the gap this bound does not cover.
    /// </summary>
    private static readonly TimeSpan TimingBound = TimeSpan.FromMilliseconds(50);

    private const int TimedSamples = 4;

    private readonly ITestOutputHelper _output;
    private Host _host = null!;

    public EnumerationResponseTests(ITestOutputHelper output)
    {
        _output = output;
    }

    public async Task InitializeAsync()
    {
        _host = await Host.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _host.DisposeAsync();
    }

    [Fact]
    public void Options_HaveNoEnumerationSwitch()
    {
        var options = typeof(AuthEndpointsOptions).Assembly.GetExportedTypes()
            .Where(type => type.Name.EndsWith("Options", StringComparison.Ordinal));
        foreach (var type in options)
        {
            Assert.DoesNotContain(
                type.GetProperties(),
                property => property.Name.Contains("Enumerat", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public async Task Register_KnownAndUnknown_MatchAndNotifiesOwner()
    {
        var known = Email("register-known");
        await _host.SeedAsync(known, confirmed: true);

        var created = await PostAsync("/identity/register", new { email = Email("register-new"), password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, created.Response.StatusCode);
        Assert.Equal("", created.Body);
        Assert.Contains(_host.Mail.Snapshot(), item => item.Kind == "confirm" && item.Email.EndsWith("@test.local", StringComparison.Ordinal));

        var duplicate = await PostAsync("/identity/register", new { email = known, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, duplicate.Response.StatusCode);
        Assert.Equal("", duplicate.Body);
        Assert.DoesNotContain("DuplicateUserName", duplicate.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("DuplicateEmail", duplicate.Body, StringComparison.Ordinal);
        Assert.Equal(1, await _host.CountUsersAsync(known));
        Assert.Contains(_host.Mail.Snapshot(), item => item.Email == known && item.Kind == "registration-attempt");
        Assert.DoesNotContain(_host.Mail.Snapshot(), item => item.Email == known && item.Kind == "confirm");

        var fresh = Email("register-fresh");
        var freshResponse = await PostAsync("/identity/register", new { email = fresh, password = TestHelpers.DefaultPassword });
        AssertSame(duplicate, freshResponse, compareBody: true);
        Assert.Contains(_host.Mail.Snapshot(), item => item.Email == fresh && item.Kind == "confirm");
        Assert.DoesNotContain(_host.Mail.Snapshot(), item => item.Email == fresh && item.Kind == "registration-attempt");

        var shortKnown = await PostAsync("/identity/register", new { email = known, password = "abc" });
        var shortUnknown = await PostAsync("/identity/register", new { email = Email("register-short"), password = "abc" });
        Assert.Equal(HttpStatusCode.BadRequest, shortKnown.Response.StatusCode);
        AssertSame(shortKnown, shortUnknown, compareBody: true);
        Assert.Contains("PasswordTooShort", shortKnown.Body, StringComparison.Ordinal);
        Assert.DoesNotContain(
            _host.Mail.Snapshot(),
            item => item.Kind == "registration-attempt" && item.Email.Contains("register-short", StringComparison.Ordinal));

        await AssertTimingAsync(
            "register",
            () => PostAsync("/identity/register", new { email = known, password = TestHelpers.DefaultPassword }),
            () => PostAsync("/identity/register", new { email = Email("register-time"), password = TestHelpers.DefaultPassword }));
    }

    [Fact]
    public async Task ForgotPassword_KnownAndUnknown_MatchAndResetMailOnlyForConfirmed()
    {
        var known = Email("forgot-known");
        var unconfirmed = Email("forgot-unconfirmed");
        await _host.SeedAsync(known, confirmed: true);
        await _host.SeedAsync(unconfirmed, confirmed: false);

        var knownResponse = await PostAsync("/identity/forgotPassword", new { email = known });
        var unknownEmail = Email("forgot-unknown");
        var unknownResponse = await PostAsync("/identity/forgotPassword", new { email = unknownEmail });
        var unconfirmedResponse = await PostAsync("/identity/forgotPassword", new { email = unconfirmed });

        Assert.Equal(HttpStatusCode.OK, knownResponse.Response.StatusCode);
        AssertSame(knownResponse, unknownResponse, compareBody: true);
        AssertSame(unknownResponse, unconfirmedResponse, compareBody: true);
        Assert.Contains(_host.Mail.Snapshot(), item => item.Email == known && item.Kind == "reset");
        Assert.DoesNotContain(_host.Mail.Snapshot(), item => item.Email == unknownEmail && item.Kind == "reset");
        Assert.DoesNotContain(_host.Mail.Snapshot(), item => item.Email == unconfirmed && item.Kind == "reset");

        await AssertTimingAsync(
            "forgotPassword",
            () => PostAsync("/identity/forgotPassword", new { email = known }),
            () => PostAsync("/identity/forgotPassword", new { email = Email("forgot-time") }));
    }

    [Fact]
    public async Task ResendConfirmationEmail_KnownAndUnknownBody_Match()
    {
        var known = Email("resend-known");
        await _host.SeedAsync(known, confirmed: true);
        var jar = new Jar();
        var login = await SendAsync(HttpMethod.Post, "/identity/login", new { email = known, password = TestHelpers.DefaultPassword }, jar, csrf: false);
        Assert.True(login.Response.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent, login.Body);

        var knownResponse = await SendAsync(HttpMethod.Post, "/identity/resendConfirmationEmail", new { email = known }, jar, csrf: true);
        var unknownResponse = await SendAsync(
            HttpMethod.Post,
            "/identity/resendConfirmationEmail",
            new { email = Email("resend-unknown") },
            jar,
            csrf: true);

        Assert.Equal(HttpStatusCode.OK, knownResponse.Response.StatusCode);
        AssertSame(knownResponse, unknownResponse, compareBody: true);
        Assert.Equal(2, _host.Mail.Snapshot().Count(item => item.Email == known && item.Kind == "confirm"));
        Assert.DoesNotContain(_host.Mail.Snapshot(), item => item.Email.Contains("resend-unknown", StringComparison.Ordinal));

        await AssertTimingAsync(
            "resendConfirmationEmail",
            () => SendAsync(HttpMethod.Post, "/identity/resendConfirmationEmail", new { email = known }, jar, csrf: true),
            () => SendAsync(HttpMethod.Post, "/identity/resendConfirmationEmail", new { email = Email("resend-time") }, jar, csrf: true));
    }

    [Fact]
    public async Task EmailCodeSend_KnownAndUnknown_Match()
    {
        var known = Email("code-known");
        await _host.SeedAsync(known, confirmed: true);

        var knownResponse = await PostAsync("/identity/emailCode/send", new { email = known });
        var unknownEmail = Email("code-unknown");
        var unknownResponse = await PostAsync("/identity/emailCode/send", new { email = unknownEmail });

        Assert.Equal(HttpStatusCode.OK, knownResponse.Response.StatusCode);
        AssertSame(knownResponse, unknownResponse, compareBody: true);
        using (var doc = JsonDocument.Parse(knownResponse.Body))
        {
            Assert.True(doc.RootElement.TryGetProperty("expiresInSeconds", out _));
            Assert.True(doc.RootElement.TryGetProperty("resendAfterSeconds", out _));
        }

        Assert.Contains(_host.Mail.Snapshot(), item => item.Email == known && item.Kind == "email-code");
        Assert.DoesNotContain(_host.Mail.Snapshot(), item => item.Email == unknownEmail && item.Kind == "email-code");

        await AssertTimingAsync(
            "emailCode/send",
            () => PostAsync("/identity/emailCode/send", new { email = known }),
            () => PostAsync("/identity/emailCode/send", new { email = Email("code-time") }));
    }

    [Fact]
    public async Task PasskeyRegisterOptions_KnownAndUnknown_Match()
    {
        var known = Email("passkey-known");
        await _host.SeedAsync(known, confirmed: true);
        var jar = new Jar();

        var knownResponse = await SendAsync(HttpMethod.Post, "/account/passkeys/register/options", new { email = known }, jar, csrf: true);
        var unknownResponse = await SendAsync(
            HttpMethod.Post,
            "/account/passkeys/register/options",
            new { email = Email("passkey-unknown") },
            jar,
            csrf: true);

        Assert.Equal(HttpStatusCode.OK, knownResponse.Response.StatusCode);
        AssertSame(knownResponse, unknownResponse, compareBody: false);
        Assert.Equal(JsonShape(knownResponse.Body), JsonShape(unknownResponse.Body));
        Assert.Contains("challenge", knownResponse.Body, StringComparison.Ordinal);

        await AssertTimingAsync(
            "passkeys/register/options",
            () => SendAsync(HttpMethod.Post, "/account/passkeys/register/options", new { email = known }, jar, csrf: true),
            () => SendAsync(HttpMethod.Post, "/account/passkeys/register/options", new { email = Email("passkey-time") }, jar, csrf: true),
            compareBody: false);
    }

    [Fact]
    public async Task PasskeyRegister_KnownAndUnknown_Match()
    {
        var known = Email("passkey-register-known");
        await _host.SeedAsync(known, confirmed: true);
        var jar = new Jar();
        var body = new { email = known, credentialJson = "{}" };

        var knownResponse = await SendAsync(HttpMethod.Post, "/account/passkeys/register", body, jar, csrf: true);
        var unknownResponse = await SendAsync(
            HttpMethod.Post,
            "/account/passkeys/register",
            new { email = Email("passkey-register-unknown"), credentialJson = "{}" },
            jar,
            csrf: true);

        Assert.Equal(HttpStatusCode.BadRequest, knownResponse.Response.StatusCode);
        AssertSame(knownResponse, unknownResponse, compareBody: true);
        Assert.Contains("Unable to complete registration.", knownResponse.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("InvalidPasskeyState", knownResponse.Body, StringComparison.Ordinal);
        Assert.Equal(1, await _host.CountUsersAsync(known));
        Assert.DoesNotContain(_host.Mail.Snapshot(), mail => mail.Email == known && mail.Kind == "confirm");

        await AssertTimingAsync(
            "passkeys/register",
            () => SendAsync(HttpMethod.Post, "/account/passkeys/register", new { email = known, credentialJson = "{}" }, jar, csrf: true),
            () => SendAsync(
                HttpMethod.Post,
                "/account/passkeys/register",
                new { email = Email("passkey-register-time"), credentialJson = "{}" },
                jar,
                csrf: true));
    }

    [Fact]
    public async Task Register_DuplicateUserNameWithoutThatEmail_ReturnsOk()
    {
        var email = Email("register-username");
        var ownerEmail = Email("register-username-owner");
        await _host.SeedAsync(ownerEmail, confirmed: true, userName: email);

        var response = await PostAsync("/identity/register", new { email, password = TestHelpers.DefaultPassword });

        Assert.Equal(HttpStatusCode.OK, response.Response.StatusCode);
        Assert.Equal(string.Empty, response.Body);
        Assert.Equal(0, await _host.CountUsersAsync(email));
        Assert.Equal(1, await _host.CountUsersAsync(ownerEmail));
        Assert.DoesNotContain(
            _host.Mail.Snapshot(),
            mail => mail.Email == email && mail.Kind == "registration-attempt");
    }

    private async Task AssertTimingAsync(
        string route,
        Func<Task<Captured>> known,
        Func<Task<Captured>> unknown,
        bool compareBody = true)
    {
        var warmupKnown = await known();
        var warmupUnknown = await unknown();
        AssertSame(warmupKnown, warmupUnknown, compareBody);

        var diffs = new long[TimedSamples];
        for (var i = 0; i < TimedSamples; i++)
        {
            var knownSample = await known();
            var unknownSample = await unknown();
            AssertSame(knownSample, unknownSample, compareBody);
            diffs[i] = Math.Abs(knownSample.ElapsedMilliseconds - unknownSample.ElapsedMilliseconds);
        }

        Array.Sort(diffs);
        var median = diffs[diffs.Length / 2];
        _output.WriteLine($"{route} timing diffs ms: {string.Join(", ", diffs)}; median {median}");
        Assert.True(
            median <= TimingBound.TotalMilliseconds,
            $"{route} median timing difference {median}ms exceeds {TimingBound.TotalMilliseconds}ms.");
    }

    private static void AssertSame(Captured known, Captured unknown, bool compareBody)
    {
        Assert.Equal(known.Response.StatusCode, unknown.Response.StatusCode);
        Assert.Equal(known.Headers, unknown.Headers);
        if (compareBody)
        {
            Assert.Equal(known.Body, unknown.Body);
        }
    }

    private Task<Captured> PostAsync(string path, object body)
        => SendAsync(HttpMethod.Post, path, body, jar: null, csrf: false);

    private async Task<Captured> SendAsync(HttpMethod method, string path, object? body, Jar? jar, bool csrf)
    {
        string? token = null;
        if (csrf)
        {
            token = await CsrfAsync(jar!);
        }

        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        if (token is not null)
        {
            request.Headers.TryAddWithoutValidation("RequestVerificationToken", token);
        }

        request.Headers.TryAddWithoutValidation("Origin", _host.Client.BaseAddress!.GetLeftPart(UriPartial.Authority));
        jar?.Apply(request, _host.Client.BaseAddress!);

        var watch = Stopwatch.StartNew();
        var response = await _host.Client.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        watch.Stop();
        jar?.Capture(response, _host.Client.BaseAddress!);
        return new Captured(response, text, HeaderSignature(response), watch.ElapsedMilliseconds);
    }

    private async Task<string> CsrfAsync(Jar jar)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/identity/csrfToken");
        jar.Apply(request, _host.Client.BaseAddress!);
        var response = await _host.Client.SendAsync(request);
        jar.Capture(response, _host.Client.BaseAddress!);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        if (doc.RootElement.TryGetProperty("csrfToken", out var camel))
        {
            return camel.GetString()!;
        }

        return doc.RootElement.GetProperty("CsrfToken").GetString()!;
    }

    private static string HeaderSignature(HttpResponseMessage response)
    {
        var lines = response.Headers
            .Concat(response.Content.Headers)
            .Where(header => !IsVolatile(header.Key))
            .OrderBy(header => header.Key, StringComparer.OrdinalIgnoreCase)
            .Select(header => header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase)
                ? "Set-Cookie=" + string.Join(",", header.Value.Select(value => value.Split('=', 2)[0]).OrderBy(name => name, StringComparer.Ordinal))
                : header.Key + "=" + string.Join(",", header.Value));
        return string.Join("\n", lines);
    }

    private static bool IsVolatile(string name)
    {
        return name.Equals("Date", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("X-Rate-Limit-", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("RateLimit-", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("X-RateLimit-", StringComparison.OrdinalIgnoreCase);
    }

    private static string JsonShape(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return Shape(doc.RootElement);
    }

    private static string Shape(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var properties = element.EnumerateObject()
                    .OrderBy(property => property.Name, StringComparer.Ordinal)
                    .Select(property => property.Name + ":" + Shape(property.Value));
                return "{" + string.Join(",", properties) + "}";
            case JsonValueKind.Array:
                return "[" + string.Join(",", element.EnumerateArray().Select(Shape)) + "]";
            default:
                return element.ValueKind.ToString();
        }
    }

    private static string Email(string label) => $"{label}-{Guid.NewGuid():N}@test.local";

    private sealed record Captured(HttpResponseMessage Response, string Body, string Headers, long ElapsedMilliseconds);

    private sealed class Jar
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

    private sealed class Host : IAsyncDisposable
    {
        // Keeps the in-memory database alive for the host's lifetime.
        private readonly SqliteConnection _keepAlive;

        private Host(WebApplication app, SqliteConnection keepAlive, CapturingEmailSender mail)
        {
            App = app;
            _keepAlive = keepAlive;
            Mail = mail;
            Client = app.GetTestClient();
            Client.BaseAddress = new Uri("http://localhost");
        }

        public WebApplication App { get; }

        public HttpClient Client { get; }

        public CapturingEmailSender Mail { get; }

        public static async Task<Host> StartAsync()
        {
            // In-memory storage: the timing checks compare endpoint work, so a new account's insert
            // must not wait on disk sync that the duplicate branch never does.
            var connectionString = $"Data Source=ae-enum-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
            var keepAlive = new SqliteConnection(connectionString);
            await keepAlive.OpenAsync();
            var mail = new CapturingEmailSender();
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = Environments.Development
            });
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<TestDbContext>(options =>
                options.UseSqlite(connectionString));
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
            builder.Services.AddSingleton(mail);
            builder.Services.AddSingleton<IEmailSender<TestAppUser>>(mail);
            builder.Services.AddSingleton<IEmailCodeSender<TestAppUser>>(mail);
            builder.Services.AddSingleton<IAccountSecurityEmailSender<TestAppUser>>(mail);
            builder.Services.AddAuthorization();
            builder.Services.AddAntiforgery();
            builder.Services.AddCookieAuthEndpoints();
            builder.Services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>(options =>
            {
                options.ResendCooldown = TimeSpan.Zero;
                options.MaxSendsPerEmail = 100;
                options.SendsPerIpPerMinute = 100;
            });
            builder.Services.AddPasskeyEndpoints<TestAppUser>();
            builder.Services.Configure<IdentityPasskeyOptions>(options => options.ServerDomain = "localhost");

            var app = builder.Build();
            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                await db.Database.EnsureCreatedAsync();
            }

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseAntiforgery();
            var identity = app.MapGroup("/identity");
            identity.MapPasswordEndpoints<TestAppUser>();
            identity.MapCookieSessionEndpoints<TestAppUser>();
            identity.MapEmailCodeEndpoints<TestAppUser>();
            var account = app.MapGroup("/account");
            account.MapPasskeyRegisterOptionsEndpoints<TestAppUser>();
            account.MapPasskeySignUpEndpoints<TestAppUser>("EnumerationPasskeyConfirmEmail");
            await app.StartAsync();
            return new Host(app, keepAlive, mail);
        }

        public Task SeedAsync(string email, bool confirmed) => SeedAsync(email, confirmed, userName: null);

        public async Task SeedAsync(string email, bool confirmed, string? userName)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = new TestAppUser
            {
                UserName = userName ?? email,
                Email = email,
                EmailConfirmed = confirmed
            };
            var created = await users.CreateAsync(user, TestHelpers.DefaultPassword);
            Assert.True(created.Succeeded, string.Join("; ", created.Errors.Select(error => error.Description)));
        }

        public async Task<int> CountUsersAsync(string email)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var normalized = users.NormalizeEmail(email);
            return await users.Users.CountAsync(user => user.NormalizedEmail == normalized);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await App.StopAsync();
            await App.DisposeAsync();
            await _keepAlive.DisposeAsync();
        }
    }
}
