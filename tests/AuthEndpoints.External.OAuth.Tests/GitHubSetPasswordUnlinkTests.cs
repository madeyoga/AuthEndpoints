using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using AuthEndpoints.EmailCode;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.Identity;
using AuthEndpoints.OAuth.GitHub;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.External.OAuth.Tests;

public class GitHubSetPasswordUnlinkTests
{
    [Fact]
    public async Task GitHub_sign_up_set_password_with_reauth_then_password_login_unlinks()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ae-github-e2e-{Guid.NewGuid():N}.sqlite");
        var mail = new Mailbox();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<FlowDb>(options => options.UseSqlite($"Data Source={path};Pooling=False"));
        builder.Services.AddIdentityApiEndpoints<FlowUser>(identity =>
            {
                identity.SignIn.RequireConfirmedAccount = false;
                identity.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                identity.Password.RequireDigit = false;
                identity.Password.RequireLowercase = false;
                identity.Password.RequireUppercase = false;
                identity.Password.RequireNonAlphanumeric = false;
                identity.Password.RequiredLength = 6;
            })
            .AddEntityFrameworkStores<FlowDb>()
            .AddDefaultTokenProviders();
        builder.Services.AddSingleton<IEmailCodeSender<FlowUser>>(mail);
        builder.Services.AddSingleton<IAccountSecurityEmailSender<FlowUser>>(mail);
        builder.Services.AddPasswordSignInEndpoints();
        builder.Services.AddCookieSessionEndpoints();
        builder.Services.AddAccountManagementEndpoints();
        builder.Services.AddEmailCodeEndpoints<FlowUser, FlowDb>();
        builder.Services.AddExternalAuthEndpoints<FlowUser>(options => options.DefaultReturnUrl = "/")
            .AddGitHub(github =>
            {
                github.ClientId = "test-client";
                github.ClientSecret = "test-secret";
            });

        await using var app = builder.Build();
        try
        {
            using (var scope = app.Services.CreateScope())
            {
                await scope.ServiceProvider.GetRequiredService<FlowDb>().Database.EnsureCreatedAsync();
            }

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseRateLimiter();
            app.UseAntiforgery();

            var external = app.MapGroup("/auth/external");
            external.MapExternalAuthProvider<FlowUser>("GitHub");
            external.MapExternalAccountEndpoints<FlowUser>();
            var auth = app.MapGroup("/auth");
            auth.MapPasswordSignInEndpoints<FlowUser>();
            auth.MapCookieSessionEndpoints<FlowUser>();
            auth.MapAccountManagementEndpoints<FlowUser>();
            app.MapPost("/test/external-cookie", async (HttpContext http) =>
            {
                var claims = new List<Claim>
                {
                    new(ClaimTypes.NameIdentifier, "github-key-1"),
                    new(ClaimTypes.Email, "github-user@example.com"),
                    new(ExternalEmailClaims.EmailVerifiedClaimType, "true"),
                };
                var identity = new ClaimsIdentity(claims, IdentityConstants.ExternalScheme);
                var properties = new AuthenticationProperties();
                properties.Items["LoginProvider"] = "GitHub";
                await http.SignInAsync(IdentityConstants.ExternalScheme, new ClaimsPrincipal(identity), properties);
                return Results.NoContent();
            });
            await app.StartAsync();

            var client = new JarClient(app);
            Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/test/external-cookie")).StatusCode);
            var callback = await client.GetAsync("/auth/external/login/github/callback?returnUrl=%2Fdashboard");
            Assert.True(callback.StatusCode == HttpStatusCode.Redirect, await callback.Content.ReadAsStringAsync());
            Assert.Equal("/dashboard", callback.Headers.Location?.ToString());

            var listed = await client.GetAsync("/auth/external/logins");
            var listedBody = await listed.Content.ReadAsStringAsync();
            Assert.True(listed.StatusCode == HttpStatusCode.OK, listedBody);
            Assert.Contains("GitHub", listedBody, StringComparison.Ordinal);
            Assert.False(EmailCodeSignInMap.IsMapped(app.Services));

            var csrf = await client.CsrfAsync("/auth/csrfToken");
            var sent = await client.PostAsJsonAsync("/auth/confirmIdentity/emailCode/send", new { }, csrf);
            Assert.True(sent.StatusCode == HttpStatusCode.OK, await sent.Content.ReadAsStringAsync());
            var code = Assert.Single(mail.Codes);
            Assert.Equal(EmailCodePurpose.ReAuth, code.Purpose);

            csrf = await client.CsrfAsync("/auth/csrfToken");
            var confirmed = await client.PostAsJsonAsync("/auth/confirmIdentity", new { emailCode = code.Code }, csrf);
            Assert.True(confirmed.StatusCode == HttpStatusCode.OK, await confirmed.Content.ReadAsStringAsync());

            csrf = await client.CsrfAsync("/auth/csrfToken");
            var tooSoon = await client.DeleteAsync("/auth/external/logins/GitHub/github-key-1", csrf);
            var tooSoonBody = await tooSoon.Content.ReadAsStringAsync();
            Assert.True(tooSoon.StatusCode == HttpStatusCode.BadRequest, tooSoonBody);
            Assert.Contains("last_signin_method", tooSoonBody, StringComparison.Ordinal);

            csrf = await client.CsrfAsync("/auth/csrfToken");
            var set = await client.PostAsJsonAsync("/auth/manage/password", new { newPassword = "Passw0rd" }, csrf);
            Assert.True(set.StatusCode == HttpStatusCode.OK, await set.Content.ReadAsStringAsync());

            csrf = await client.CsrfAsync("/auth/csrfToken");
            var logout = await client.PostAsJsonAsync("/auth/logout", new { }, csrf);
            Assert.True(
                logout.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
                await logout.Content.ReadAsStringAsync());

            var login = await client.PostAsJsonAsync("/auth/login", new { email = "github-user@example.com", password = "Passw0rd" });
            Assert.True(
                login.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
                await login.Content.ReadAsStringAsync());

            csrf = await client.CsrfAsync("/auth/csrfToken");
            var passwordProof = await client.PostAsJsonAsync("/auth/confirmIdentity", new { password = "Passw0rd" }, csrf);
            Assert.True(passwordProof.StatusCode == HttpStatusCode.OK, await passwordProof.Content.ReadAsStringAsync());

            csrf = await client.CsrfAsync("/auth/csrfToken");
            var unlinked = await client.DeleteAsync("/auth/external/logins/GitHub/github-key-1", csrf);
            Assert.True(unlinked.StatusCode == HttpStatusCode.NoContent, await unlinked.Content.ReadAsStringAsync());

            var after = await client.GetAsync("/auth/external/logins");
            using var doc = JsonDocument.Parse(await after.Content.ReadAsStringAsync());
            Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
            Assert.Equal(0, doc.RootElement.GetArrayLength());
            client.Dispose();
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private sealed class Mailbox : IEmailCodeSender<FlowUser>, IAccountSecurityEmailSender<FlowUser>
    {
        public List<EmailCodeMessage<FlowUser>> Codes { get; } = new();

        public Task SendSignInCodeAsync(EmailCodeMessage<FlowUser> message, CancellationToken cancellationToken = default)
        {
            Codes.Add(message);
            return Task.CompletedTask;
        }

        public Task SendPasswordSetAsync(FlowUser user, string email, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task SendRegistrationAttemptedAsync(FlowUser user, string email, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
