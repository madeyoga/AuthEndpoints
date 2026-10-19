using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.Tests;

public class EmailCodeConfirmIdentitySendTests
{
    [Fact]
    public async Task SignInOnlyEmailCode_WithAccountManagement_ConfirmIdentityEmailCodeSendIsUnmapped()
    {
        await using var host = await SendHost.StartSignInOnlyAsync();
        var email = $"signin-only-{Guid.NewGuid():N}@test.local";
        await host.SeedPasswordlessAsync(email);
        var jar = await host.SignInWithIssuedCodeAsync(email, "/identity");

        var sent = await host.PostCsrfAsync(jar, "/identity/confirmIdentity/emailCode/send", "/identity/csrfToken");
        var body = await sent.Content.ReadAsStringAsync();
        Assert.True(
            sent.StatusCode == HttpStatusCode.NotFound,
            $"POST /identity/confirmIdentity/emailCode/send returned {(int)sent.StatusCode}: {body}");
        Assert.False(await host.EmailCodeOfferedAsync(jar, "/identity/manage/authMethods"));

        var confirm = await host.PostCsrfAsync(
            jar,
            "/identity/confirmIdentity",
            "/identity/csrfToken",
            new { emailCode = "000000" });
        var confirmBody = await confirm.Content.ReadAsStringAsync();
        Assert.True(
            confirm.StatusCode == HttpStatusCode.BadRequest,
            $"POST /identity/confirmIdentity returned {(int)confirm.StatusCode}: {confirmBody}");
        using var confirmDoc = JsonDocument.Parse(confirmBody);
        Assert.Equal("EmailCodeProofUnavailable", confirmDoc.RootElement.GetProperty("title").GetString());
    }

    [Fact]
    public async Task SendOnlyEmailCode_WithAccountManagement_OffersEmailCodeAndSends()
    {
        await using var host = await SendHost.StartSendOnlyAsync();
        var email = $"send-only-{Guid.NewGuid():N}@test.local";
        await host.SeedPasswordlessAsync(email);
        var jar = await host.SignInDirectlyAsync(email);

        Assert.True(await host.EmailCodeOfferedAsync(jar, "/identity/manage/authMethods"));

        var sent = await host.PostCsrfAsync(jar, "/identity/confirmIdentity/emailCode/send", "/identity/csrfToken");
        var body = await sent.Content.ReadAsStringAsync();
        Assert.True(
            sent.StatusCode == HttpStatusCode.OK,
            $"POST /identity/confirmIdentity/emailCode/send returned {(int)sent.StatusCode}: {body}");
        using var doc = JsonDocument.Parse(body);
        Assert.True(
            doc.RootElement.TryGetProperty("expiresInSeconds", out _)
            || doc.RootElement.TryGetProperty("ExpiresInSeconds", out _));
        Assert.Contains(host.Mail.Snapshot(), item => item.Email == email && item.Purpose == EmailCodePurpose.ReAuth);
    }

    [Fact]
    public async Task PasswordAuth_WithEmailCodeEndpoints_SendsConfirmIdentityEmailCode()
    {
        await using var host = await SendHost.StartPasswordAuthAsync();
        var email = $"password-auth-{Guid.NewGuid():N}@test.local";
        await host.SeedPasswordlessAsync(email);

        var signInSend = await host.PostAsync("/auth/emailCode/send", new { email });
        Assert.Equal(HttpStatusCode.OK, signInSend.StatusCode);
        var code = host.Mail.Snapshot().Single(item => item.Email == email && item.Purpose == EmailCodePurpose.SignIn).Body;

        var jar = new CookieJar();
        var verify = await host.PostAsync(
            "/auth/emailCode/verify?useSessionCookies=true",
            new { email, code },
            jar);
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
        Assert.True(await host.EmailCodeOfferedAsync(jar, "/auth/manage/authMethods"));

        var sent = await host.PostCsrfAsync(jar, "/auth/confirmIdentity/emailCode/send", "/auth/csrfToken");
        var body = await sent.Content.ReadAsStringAsync();
        Assert.True(
            sent.StatusCode == HttpStatusCode.OK,
            $"POST /auth/confirmIdentity/emailCode/send returned {(int)sent.StatusCode}: {body}");
        using var doc = JsonDocument.Parse(body);
        Assert.True(
            doc.RootElement.TryGetProperty("expiresInSeconds", out _)
            || doc.RootElement.TryGetProperty("ExpiresInSeconds", out _));
        Assert.Contains(host.Mail.Snapshot(), item => item.Email == email && item.Purpose == EmailCodePurpose.ReAuth);
    }

    private sealed class SendHost : IAsyncDisposable
    {
        private readonly string _path;

        private SendHost(WebApplication app, string path, CapturingEmailSender mail)
        {
            App = app;
            _path = path;
            Mail = mail;
            Client = app.GetTestClient();
        }

        public WebApplication App { get; }

        public HttpClient Client { get; }

        public CapturingEmailSender Mail { get; }

        public static Task<SendHost> StartSignInOnlyAsync()
        {
            return StartAsync(
                services =>
                {
                    services.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>();
                    services.AddCookieSessionEndpoints();
                    services.AddAccountManagementEndpoints();
                    services.AddEmailCodeSignInEndpoints<TestAppUser, TestDbContext>();
                },
                app =>
                {
                    var group = app.MapGroup("/identity");
                    group.MapCookieSessionEndpoints<TestAppUser>();
                    group.MapEmailCodeSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
                    group.MapAccountManagementEndpoints<TestAppUser>();
                });
        }

        public static Task<SendHost> StartSendOnlyAsync()
        {
            return StartAsync(
                services =>
                {
                    services.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>();
                    services.AddCookieSessionEndpoints();
                    services.AddAccountManagementEndpoints();
                    services.AddEmailCodeSendEndpoints<TestAppUser, TestDbContext>();
                },
                app =>
                {
                    var group = app.MapGroup("/identity");
                    group.MapCookieSessionEndpoints<TestAppUser>();
                    group.MapAccountManagementEndpoints<TestAppUser>();
                    app.MapPost("/test/sign-in", async (string email, SignInManager<TestAppUser> signIn, UserManager<TestAppUser> users) =>
                    {
                        var user = await users.FindByEmailAsync(email);
                        await signIn.SignInAsync(user!, isPersistent: false);
                        return Results.NoContent();
                    });
                });
        }

        public static Task<SendHost> StartPasswordAuthAsync()
        {
            return StartAsync(
                services =>
                {
                    services.AddPasswordAuth<TestAppUser, TestDbContext>();
                    services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>();
                },
                app =>
                {
                    app.MapPasswordAuth<TestAppUser>();
                    app.MapGroup("/auth").MapEmailCodeEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
                });
        }

        public async Task SeedPasswordlessAsync(string email)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = new TestAppUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true
            };
            var created = await users.CreateAsync(user);
            Assert.True(created.Succeeded, string.Join("; ", created.Errors.Select(error => error.Description)));
        }

        public async Task<CookieJar> SignInWithIssuedCodeAsync(string email, string prefix)
        {
            string code;
            using (var scope = App.Services.CreateScope())
            {
                var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
                var store = scope.ServiceProvider.GetRequiredService<IEmailCodeStore>();
                var user = await users.FindByEmailAsync(email);
                Assert.NotNull(user);
                var issued = await store.IssueAsync(
                    email,
                    await users.GetUserIdAsync(user),
                    await users.GetSecurityStampAsync(user),
                    EmailCodeRowPurpose.SignIn);
                Assert.False(issued.Suppressed, issued.SuppressedReason);
                code = issued.Code;
            }

            var jar = new CookieJar();
            var verify = await PostAsync($"{prefix}/emailCode/verify?useSessionCookies=true", new { email, code }, jar);
            Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
            return jar;
        }

        public async Task<CookieJar> SignInDirectlyAsync(string email)
        {
            var jar = new CookieJar();
            var response = await PostAsync($"/test/sign-in?email={Uri.EscapeDataString(email)}", new { }, jar);
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            return jar;
        }

        public async Task<bool> EmailCodeOfferedAsync(CookieJar jar, string path)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            jar.Apply(request, Client.BaseAddress!);
            var response = await Client.SendAsync(request);
            jar.Capture(response, Client.BaseAddress!);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (doc.RootElement.TryGetProperty("emailCode", out var camel))
            {
                return camel.GetBoolean();
            }

            return doc.RootElement.GetProperty("EmailCode").GetBoolean();
        }

        public Task<HttpResponseMessage> PostAsync(string path, object body, CookieJar? jar = null)
        {
            return SendAsync(HttpMethod.Post, path, body, jar, csrf: null);
        }

        public async Task<HttpResponseMessage> PostCsrfAsync(CookieJar jar, string path, string csrfPath, object? body = null)
        {
            using var csrfRequest = new HttpRequestMessage(HttpMethod.Get, csrfPath);
            jar.Apply(csrfRequest, Client.BaseAddress!);
            var csrfResponse = await Client.SendAsync(csrfRequest);
            jar.Capture(csrfResponse, Client.BaseAddress!);
            Assert.Equal(HttpStatusCode.OK, csrfResponse.StatusCode);
            using var doc = JsonDocument.Parse(await csrfResponse.Content.ReadAsStringAsync());
            var token = doc.RootElement.TryGetProperty("csrfToken", out var camel)
                ? camel.GetString()
                : doc.RootElement.GetProperty("CsrfToken").GetString();
            Assert.False(string.IsNullOrEmpty(token));
            return await SendAsync(HttpMethod.Post, path, body ?? new { }, jar, token);
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

        private static async Task<SendHost> StartAsync(
            Action<IServiceCollection> configure,
            Action<WebApplication> map)
        {
            var path = Path.Combine(Path.GetTempPath(), $"ae-email-code-send-{Guid.NewGuid():N}.sqlite");
            var mail = new CapturingEmailSender();
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = Environments.Development
            });
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<TestDbContext>(options =>
                options.UseSqlite($"Data Source={path}"));
            builder.Services.AddSingleton(mail);
            builder.Services.AddSingleton<IEmailSender<TestAppUser>>(mail);
            builder.Services.AddSingleton<IEmailCodeSender<TestAppUser>>(mail);
            builder.Services.AddSingleton<IAccountSecurityEmailSender<TestAppUser>>(mail);
            configure(builder.Services);

            var app = builder.Build();
            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                await db.Database.EnsureDeletedAsync();
                await db.Database.EnsureCreatedAsync();
            }

            app.UseAuthEndpoints();
            map(app);
            await app.StartAsync();
            return new SendHost(app, path, mail);
        }

        private async Task<HttpResponseMessage> SendAsync(
            HttpMethod method,
            string path,
            object? body,
            CookieJar? jar,
            string? csrf)
        {
            using var request = new HttpRequestMessage(method, path);
            if (body is not null)
            {
                request.Content = JsonContent.Create(body);
            }

            if (!string.IsNullOrEmpty(csrf))
            {
                request.Headers.TryAddWithoutValidation("RequestVerificationToken", csrf);
            }

            if (Client.BaseAddress is not null)
            {
                request.Headers.TryAddWithoutValidation("Origin", Client.BaseAddress.GetLeftPart(UriPartial.Authority));
                jar?.Apply(request, Client.BaseAddress);
            }

            var response = await Client.SendAsync(request);
            if (Client.BaseAddress is not null)
            {
                jar?.Capture(response, Client.BaseAddress);
            }

            return response;
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
}
