using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using AuthEndpoints.Identity;
using AuthEndpoints.Passkey;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AuthEndpoints.External.OAuth.Tests;

public class ExternalReAuthTests
{
    private const string Fake = "FakeIdp";
    private const string Other = "OtherIdp";
    private const string Oidc = "OidcIdp";

    [Fact]
    public async Task External_only_account_without_email_code_steps_up_then_adds_passkey_enables_2fa_and_sets_password()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        var userId = await host.SignInExternalOnlyAsync(client, Fake, "fake-key");

        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/auth/passkeys/creationOptions", new { }, await host.CsrfAsync(client))).StatusCode);

        await host.StepUpCookieAsync(client, Fake, "fake-key");
        var options = await client.PostAsJsonAsync("/auth/passkeys/creationOptions", new { }, await host.CsrfAsync(client));
        Assert.True(options.StatusCode == HttpStatusCode.OK, await options.Content.ReadAsStringAsync());

        var authenticatorCode = await host.AuthenticatorCodeAsync(userId);
        await host.StepUpCookieAsync(client, Fake, "fake-key");
        var twoFactor = await client.PostAsJsonAsync("/auth/manage/2fa", new { enable = true, twoFactorCode = authenticatorCode }, await host.CsrfAsync(client));
        Assert.True(twoFactor.StatusCode == HttpStatusCode.OK, await twoFactor.Content.ReadAsStringAsync());

        await host.StepUpCookieAsync(client, Fake, "fake-key");
        var password = await client.PostAsJsonAsync("/auth/manage/password", new { newPassword = "Passw0rd" }, await host.CsrfAsync(client));
        Assert.True(password.StatusCode == HttpStatusCode.OK, await password.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Cookie_client_gets_reauth_cookie_and_no_token_in_url()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");

        var (callback, _) = await host.StepUpCookieAsync(client, Fake, "fake-key", returnUrl: "/settings");
        Assert.Equal("/settings", callback.Headers.Location?.ToString());
        Assert.Contains(callback.Headers.GetValues("Set-Cookie"), c => c.StartsWith(AuthEndpointsConstants.ReAuthScheme + "=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Bearer_client_gets_one_time_code_and_exchanges_it_for_token()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        var userId = await host.CreateLinkedUserAsync(Fake, "fake-key");
        var bearer = await host.BearerTokenAsync(userId);

        var start = await client.SendWithBearerAsync(HttpMethod.Post, $"/auth/confirmIdentity/external/{Fake}", JsonContent.Create(new { returnUrl = "/app/done" }), bearer);
        Assert.True(start.StatusCode == HttpStatusCode.OK, await start.Content.ReadAsStringAsync());
        var callback = await host.FollowProviderAsync(client, await RedirectUrlAsync(start), Fake, "fake-key");
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        var location = callback.Headers.Location!.ToString();
        Assert.StartsWith("/app/done?reauthCode=", location, StringComparison.Ordinal);
        Assert.DoesNotContain("reauthToken", location, StringComparison.OrdinalIgnoreCase);
        Assert.False(callback.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(c => c.StartsWith(AuthEndpointsConstants.ReAuthScheme + "=", StringComparison.Ordinal)));
        var code = Uri.UnescapeDataString(location.Split("reauthCode=", 2)[1]);

        var complete = await client.SendWithBearerAsync(HttpMethod.Post, "/auth/confirmIdentity/external/complete", JsonContent.Create(new { code }), bearer);
        var body = await complete.Content.ReadAsStringAsync();
        Assert.True(complete.StatusCode == HttpStatusCode.OK, body);
        using var doc = JsonDocument.Parse(body);
        Assert.False(string.IsNullOrEmpty(doc.RootElement.GetProperty("reauthToken").GetString()));

        var reused = await client.SendWithBearerAsync(HttpMethod.Post, "/auth/confirmIdentity/external/complete", JsonContent.Create(new { code }), bearer);
        Assert.Equal(HttpStatusCode.Unauthorized, reused.StatusCode);

        var otherUser = await host.CreateLinkedUserAsync(Other, "other-key");
        var stolen = await client.SendWithBearerAsync(HttpMethod.Post, "/auth/confirmIdentity/external/complete", JsonContent.Create(new { code }), await host.BearerTokenAsync(otherUser));
        Assert.Equal(HttpStatusCode.Unauthorized, stolen.StatusCode);
    }

    [Fact]
    public async Task Callback_rejects_login_owned_by_different_user()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        await host.CreateLinkedUserAsync(Fake, "someone-else");

        var (callback, _) = await host.StepUpCookieAsync(client, Fake, "someone-else", expectSuccess: false);
        AssertRejected(callback, "user_mismatch");
        Assert.False(HasReAuthCookie(callback));
    }

    [Fact]
    public async Task Callback_rejects_unlinked_login()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");

        var (callback, _) = await host.StepUpCookieAsync(client, Fake, "never-linked", expectSuccess: false);
        AssertRejected(callback, "login_not_linked");
        Assert.False(HasReAuthCookie(callback));
    }

    [Fact]
    public async Task Start_rejects_provider_not_linked_to_user()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");

        var start = await client.PostAsJsonAsync($"/auth/confirmIdentity/external/{Other}", new { }, await host.CsrfAsync(client));
        Assert.Equal(HttpStatusCode.BadRequest, start.StatusCode);
        Assert.Contains("login_not_linked", await start.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Callback_rejects_reused_state()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        var redirect = await host.StartCookieAsync(client, Fake);
        var first = await host.FollowProviderAsync(client, redirect, Fake, "fake-key");
        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);

        var replay = await host.ReplayCallbackAsync(client, Fake, "fake-key");
        AssertRejected(replay, "invalid_request");
        Assert.False(HasReAuthCookie(replay));
    }

    [Fact]
    public async Task Callback_rejects_expired_state()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        var redirect = await host.StartCookieAsync(client, Fake);
        await host.LaunchAsync(client, redirect);
        host.Clock.Advance(TimeSpan.FromMinutes(6));

        var callback = await host.CompleteProviderAsync(client, Fake, "fake-key");
        AssertRejected(callback, "invalid_request");
        Assert.False(HasReAuthCookie(callback));
    }

    [Fact]
    public async Task Launch_rejects_expired_state()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        var redirect = await host.StartCookieAsync(client, Fake);
        host.Clock.Advance(TimeSpan.FromMinutes(6));

        var launch = await client.GetAsync(new Uri(redirect).PathAndQuery);
        AssertRejected(launch, "invalid_request");
    }

    [Fact]
    public async Task Callback_rejects_stale_auth_time()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        var stale = host.Clock.GetUtcNow().AddHours(-1).ToUnixTimeSeconds();

        var (callback, _) = await host.StepUpCookieAsync(client, Fake, "fake-key", authTime: stale, expectSuccess: false);
        AssertRejected(callback, "stale_sign_in");
    }

    [Fact]
    public async Task Callback_accepts_fresh_auth_time()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        var fresh = host.Clock.GetUtcNow().ToUnixTimeSeconds();

        var (callback, _) = await host.StepUpCookieAsync(client, Fake, "fake-key", authTime: fresh);
        Assert.True(HasReAuthCookie(callback));
    }

    [Fact]
    public async Task Callback_never_signs_in_without_a_session()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        var redirect = await host.StartCookieAsync(client, Fake);
        await host.LaunchAsync(client, redirect);
        var ticket = host.Challenges.Last().Items[ExternalReAuthEndpoints<FlowUser>.StateItem]!;

        var fresh = new JarClient(host.App);
        Assert.Equal(HttpStatusCode.NoContent, (await fresh.PostAsJsonAsync("/test/external-cookie", new { provider = Fake, key = "fake-key", ticket })).StatusCode);
        var callback = await fresh.GetAsync($"/auth/confirmIdentity/external/{Fake}/callback");
        AssertRejected(callback, "user_mismatch");
        Assert.False(HasReAuthCookie(callback));
        Assert.False(callback.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(c => c.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal) && !c.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase)));
        Assert.Equal(HttpStatusCode.Unauthorized, (await fresh.GetAsync("/auth/manage/authMethods")).StatusCode);
        fresh.Dispose();
    }

    [Fact]
    public async Task Bare_external_cookie_without_state_is_rejected()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync("/test/external-cookie", new { provider = Fake, key = "fake-key" })).StatusCode);

        var callback = await client.GetAsync($"/auth/confirmIdentity/external/{Fake}/callback");
        AssertRejected(callback, "invalid_request");
        Assert.False(HasReAuthCookie(callback));
    }

    [Fact]
    public async Task Start_requires_signed_in_user_and_antiforgery_for_cookie_sessions()
    {
        await using var host = await StepUpHost.StartAsync();
        var anonymous = new JarClient(host.App);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync($"/auth/confirmIdentity/external/{Fake}", new { })).StatusCode);
        anonymous.Dispose();

        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        var noCsrf = await client.PostAsJsonAsync($"/auth/confirmIdentity/external/{Fake}", new { });
        Assert.Equal(HttpStatusCode.BadRequest, noCsrf.StatusCode);
    }

    [Fact]
    public async Task Return_url_outside_allowlist_falls_back_to_default()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");

        var (callback, _) = await host.StepUpCookieAsync(client, Fake, "fake-key", returnUrl: "https://evil.example/steal");
        Assert.Equal("/", callback.Headers.Location?.ToString());
    }

    [Fact]
    public async Task Auth_methods_lists_linked_external_providers_only()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");

        using var doc = await AuthMethodsAsync(client);
        var root = doc.RootElement;
        Assert.Equal(
            ["password", "authenticator", "recoveryCodes", "passkeys", "passkeyCount", "emailCode", "external"],
            root.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.False(root.GetProperty("password").GetBoolean());
        Assert.False(root.GetProperty("emailCode").GetBoolean());
        var external = Assert.Single(root.GetProperty("external").EnumerateArray());
        Assert.Equal(Fake, external.GetProperty("scheme").GetString());
        Assert.Equal("Fake IdP", external.GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task Global_opt_out_hides_methods_and_404s_routes()
    {
        await using var host = await StepUpHost.StartAsync(reauth => reauth.External.Enabled = false);
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");

        using var doc = await AuthMethodsAsync(client);
        Assert.Equal(0, doc.RootElement.GetProperty("external").GetArrayLength());
        var start = await client.PostAsJsonAsync($"/auth/confirmIdentity/external/{Fake}", new { }, await host.CsrfAsync(client));
        Assert.Equal(HttpStatusCode.NotFound, start.StatusCode);
    }

    [Fact]
    public async Task Per_provider_opt_out_hides_only_that_provider()
    {
        await using var host = await StepUpHost.StartAsync(reauth => reauth.External.DisabledProviders.Add(Fake));
        var client = host.Client;
        var userId = await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        await host.AddLoginAsync(userId, Other, "other-key");

        using var doc = await AuthMethodsAsync(client);
        var external = Assert.Single(doc.RootElement.GetProperty("external").EnumerateArray());
        Assert.Equal(Other, external.GetProperty("scheme").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync($"/auth/confirmIdentity/external/{Fake}", new { }, await host.CsrfAsync(client))).StatusCode);

        var (callback, _) = await host.StepUpCookieAsync(client, Other, "other-key");
        Assert.True(HasReAuthCookie(callback));
    }

    [Fact]
    public async Task Existing_password_step_up_is_unaffected()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        var userId = await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        await host.AddPasswordAsync(userId, "Passw0rd");

        var wrong = await client.PostAsJsonAsync("/auth/confirmIdentity", new { password = "nope-nope" }, await host.CsrfAsync(client));
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        var confirmed = await client.PostAsJsonAsync("/auth/confirmIdentity", new { password = "Passw0rd" }, await host.CsrfAsync(client));
        Assert.True(confirmed.StatusCode == HttpStatusCode.OK, await confirmed.Content.ReadAsStringAsync());
        Assert.True(HasReAuthCookie(confirmed));
    }

    [Fact]
    public async Task Provider_challenge_targets_step_up_callback()
    {
        await using var host = await StepUpHost.StartAsync();
        var client = host.Client;
        await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        await host.LaunchAsync(client, await host.StartCookieAsync(client, Fake));

        var challenge = host.Challenges.Last();
        Assert.Equal($"/auth/confirmIdentity/external/{Fake}/callback", challenge.RedirectUri);
        Assert.Equal(Fake, challenge.Items["LoginProvider"]);
    }

    [Fact]
    public async Task Oidc_challenge_sends_prompt_login_and_max_age_zero()
    {
        await using var host = await StepUpHost.StartAsync(oidc: true);
        var client = host.Client;
        var userId = await host.SignInExternalOnlyAsync(client, Fake, "fake-key");
        await host.AddLoginAsync(userId, Oidc, "oidc-key");

        var launch = await client.GetAsync(new Uri(await host.StartCookieAsync(client, Oidc)).PathAndQuery);
        Assert.Equal(HttpStatusCode.Redirect, launch.StatusCode);
        var query = launch.Headers.Location!.Query;
        Assert.Contains("prompt=login", query, StringComparison.Ordinal);
        Assert.Contains("max_age=0", query, StringComparison.Ordinal);
    }

    private static void AssertRejected(HttpResponseMessage response, string error)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith($"/auth/external/error?error={error}&", response.Headers.Location?.ToString(), StringComparison.Ordinal);
        Assert.False(HasReAuthCookie(response));
    }

    private static bool HasReAuthCookie(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var cookies)
        && cookies.Any(c => c.StartsWith(AuthEndpointsConstants.ReAuthScheme + "=", StringComparison.Ordinal)
            && !c.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));

    private static async Task<string> RedirectUrlAsync(HttpResponseMessage start)
    {
        using var doc = JsonDocument.Parse(await start.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("redirectUrl").GetString()!;
    }

    private static async Task<JsonDocument> AuthMethodsAsync(JarClient client)
    {
        var response = await client.GetAsync("/auth/manage/authMethods");
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, body);
        return JsonDocument.Parse(body);
    }

    private sealed class StepUpHost : IAsyncDisposable
    {
        private readonly string _path;

        private StepUpHost(WebApplication app, string path)
        {
            App = app;
            _path = path;
            Client = new JarClient(app);
        }

        public WebApplication App { get; }
        public JarClient Client { get; }
        public TestClock Clock => App.Services.GetRequiredService<TestClock>();
        public List<AuthenticationProperties> Challenges => App.Services.GetRequiredService<ChallengeLog>().Items;

        public static async Task<StepUpHost> StartAsync(Action<AuthEndpointsReAuthOptions>? reauth = null, bool oidc = false)
        {
            var path = Path.Combine(Path.GetTempPath(), $"ae-external-reauth-{Guid.NewGuid():N}.sqlite");
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
            builder.WebHost.UseTestServer();
            var clock = new TestClock();
            builder.Services.AddSingleton(clock);
            builder.Services.Replace(ServiceDescriptor.Singleton<TimeProvider>(clock));
            builder.Services.AddSingleton<ChallengeLog>();
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
            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.Events.OnRedirectToLogin = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };
            });
            builder.Services.AddPasswordSignInEndpoints();
            builder.Services.AddCookieSessionEndpoints();
            builder.Services.AddAccountManagementEndpoints();
            builder.Services.AddPasskeyEndpoints<FlowUser>();
            builder.Services.AddExternalAuthEndpoints<FlowUser>(options =>
            {
                options.DefaultReturnUrl = "/";
                options.ErrorPath = "/auth/external/error";
            });
            if (reauth is not null)
            {
                builder.Services.Configure(reauth);
            }

            builder.Services.AddSingleton<IExternalAuthProvider>(new NamedProvider(Fake, "login/fake", "login/fake/callback", "FakeCallback"));
            builder.Services.AddSingleton<IExternalAuthProvider>(new NamedProvider(Other, "login/other", "login/other/callback", "OtherCallback"));
            var authentication = builder.Services.AddAuthentication()
                .AddScheme<AuthenticationSchemeOptions, CapturingHandler>(Fake, "Fake IdP", _ => { })
                .AddScheme<AuthenticationSchemeOptions, CapturingHandler>(Other, "Other IdP", _ => { });
            if (oidc)
            {
                builder.Services.AddSingleton<IExternalAuthProvider>(new NamedProvider(Oidc, "login/oidc", "login/oidc/callback", "OidcCallback"));
                authentication.AddOpenIdConnect(Oidc, options =>
                {
                    options.ClientId = "client";
                    options.SignInScheme = IdentityConstants.ExternalScheme;
                    options.Configuration = new OpenIdConnectConfiguration
                    {
                        AuthorizationEndpoint = "https://idp.example/authorize",
                        Issuer = "https://idp.example",
                    };
                });
            }

            var app = builder.Build();
            using (var scope = app.Services.CreateScope())
            {
                await scope.ServiceProvider.GetRequiredService<FlowDb>().Database.EnsureCreatedAsync();
            }

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseRateLimiter();
            app.UseAntiforgery();

            var auth = app.MapGroup("/auth");
            auth.MapPasswordSignInEndpoints<FlowUser>();
            auth.MapCookieSessionEndpoints<FlowUser>();
            auth.MapAccountManagementEndpoints<FlowUser>();
            auth.MapPasskeyEndpoints<FlowUser>();
            app.MapPost("/test/external-cookie", async (PlantedLogin body, HttpContext http) =>
            {
                var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, body.Key) };
                if (body.AuthTime is { } authTime)
                {
                    claims.Add(new Claim("auth_time", authTime.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                }

                var properties = new AuthenticationProperties();
                properties.Items["LoginProvider"] = body.Provider;
                if (body.Ticket is not null)
                {
                    properties.Items[ExternalReAuthEndpoints<FlowUser>.StateItem] = body.Ticket;
                }

                await http.SignInAsync(IdentityConstants.ExternalScheme, new ClaimsPrincipal(new ClaimsIdentity(claims, IdentityConstants.ExternalScheme)), properties);
                return Results.NoContent();
            });
            app.MapPost("/test/session/{userId}", async (string userId, UserManager<FlowUser> users, SignInManager<FlowUser> signIn) =>
            {
                await signIn.SignInAsync((await users.FindByIdAsync(userId))!, isPersistent: false);
                return Results.NoContent();
            });
            app.MapPost("/test/bearer/{userId}", async (string userId, UserManager<FlowUser> users, SignInManager<FlowUser> signIn) =>
            {
                var principal = await signIn.CreateUserPrincipalAsync((await users.FindByIdAsync(userId))!);
                return TypedResults.SignIn(principal, authenticationScheme: IdentityConstants.BearerScheme);
            });
            await app.StartAsync();
            return new StepUpHost(app, path);
        }

        public async Task<string> CreateLinkedUserAsync(string provider, string key)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<FlowUser>>();
            var user = new FlowUser { UserName = $"{key}@example.com", Email = $"{key}@example.com", EmailConfirmed = true };
            Assert.True((await users.CreateAsync(user)).Succeeded);
            Assert.True((await users.AddLoginAsync(user, new UserLoginInfo(provider, key, provider))).Succeeded);
            return user.Id;
        }

        public async Task AddLoginAsync(string userId, string provider, string key)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<FlowUser>>();
            Assert.True((await users.AddLoginAsync((await users.FindByIdAsync(userId))!, new UserLoginInfo(provider, key, provider))).Succeeded);
        }

        public async Task AddPasswordAsync(string userId, string password)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<FlowUser>>();
            Assert.True((await users.AddPasswordAsync((await users.FindByIdAsync(userId))!, password)).Succeeded);
        }

        public async Task<string> AuthenticatorCodeAsync(string userId)
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<FlowUser>>();
            var user = (await users.FindByIdAsync(userId))!;
            var key = await users.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await users.ResetAuthenticatorKeyAsync(user);
                key = await users.GetAuthenticatorKeyAsync(user);
            }

            return Totp(key!, DateTimeOffset.UtcNow);
        }

        private static string Totp(string base32, DateTimeOffset now)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var bits = 0;
            var value = 0;
            var bytes = new List<byte>();
            foreach (var c in base32.TrimEnd('=').ToUpperInvariant())
            {
                value = (value << 5) | alphabet.IndexOf(c, StringComparison.Ordinal);
                bits += 5;
                if (bits >= 8)
                {
                    bytes.Add((byte)(value >> (bits - 8)));
                    bits -= 8;
                }
            }

            var counter = BitConverter.GetBytes(now.ToUnixTimeSeconds() / 30);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counter);
            }

            var hash = System.Security.Cryptography.HMACSHA1.HashData(bytes.ToArray(), counter);
            var offset = hash[^1] & 0x0f;
            var code = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
            return (code % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
        }

        public async Task<string> SignInExternalOnlyAsync(JarClient client, string provider, string key)
        {
            var userId = await CreateLinkedUserAsync(provider, key);
            Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync($"/test/session/{userId}")).StatusCode);
            return userId;
        }

        public async Task<string> BearerTokenAsync(string userId)
        {
            var response = await Client.PostAsync($"/test/bearer/{userId}");
            response.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return doc.RootElement.GetProperty("accessToken").GetString()!;
        }

        public Task<string> CsrfAsync(JarClient client) => client.CsrfAsync("/auth/csrfToken");

        public async Task<string> StartCookieAsync(JarClient client, string provider, string? returnUrl = null)
        {
            var start = await client.PostAsJsonAsync($"/auth/confirmIdentity/external/{provider}", new { returnUrl }, await CsrfAsync(client));
            Assert.True(start.StatusCode == HttpStatusCode.OK, await start.Content.ReadAsStringAsync());
            return await RedirectUrlAsync(start);
        }

        public async Task LaunchAsync(JarClient client, string redirectUrl)
        {
            var uri = new Uri(redirectUrl);
            Assert.DoesNotContain("reauthToken", uri.Query, StringComparison.OrdinalIgnoreCase);
            var launch = await client.GetAsync(uri.PathAndQuery);
            Assert.True(launch.StatusCode == HttpStatusCode.Redirect, await launch.Content.ReadAsStringAsync());
            Assert.StartsWith("https://idp.test/authorize", launch.Headers.Location!.ToString(), StringComparison.Ordinal);
        }

        public async Task<HttpResponseMessage> CompleteProviderAsync(JarClient client, string provider, string key, long? authTime = null)
        {
            var challenge = Challenges.Last();
            var ticket = challenge.Items[ExternalReAuthEndpoints<FlowUser>.StateItem];
            Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync("/test/external-cookie", new { provider, key, ticket, authTime })).StatusCode);
            return await client.GetAsync(challenge.RedirectUri!);
        }

        public Task<HttpResponseMessage> ReplayCallbackAsync(JarClient client, string provider, string key) =>
            CompleteProviderAsync(client, provider, key);

        public async Task<HttpResponseMessage> FollowProviderAsync(JarClient client, string redirectUrl, string provider, string key, long? authTime = null)
        {
            await LaunchAsync(client, redirectUrl);
            return await CompleteProviderAsync(client, provider, key, authTime);
        }

        public async Task<(HttpResponseMessage Callback, string Body)> StepUpCookieAsync(
            JarClient client,
            string provider,
            string key,
            string? returnUrl = null,
            long? authTime = null,
            bool expectSuccess = true)
        {
            var redirect = await StartCookieAsync(client, provider, returnUrl);
            var callback = await FollowProviderAsync(client, redirect, provider, key, authTime);
            var body = await callback.Content.ReadAsStringAsync();
            if (expectSuccess)
            {
                Assert.True(callback.StatusCode == HttpStatusCode.Redirect, body);
                Assert.True(HasReAuthCookie(callback));
                Assert.DoesNotContain("reauth", callback.Headers.Location!.ToString(), StringComparison.OrdinalIgnoreCase);
            }

            return (callback, body);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await App.StopAsync();
            await App.DisposeAsync();
            SqliteConnection.ClearAllPools();
            try
            {
                File.Delete(_path);
            }
            catch (IOException)
            {
            }
        }
    }

    private sealed record PlantedLogin(string Provider, string Key, string? Ticket, long? AuthTime);

    private sealed class ChallengeLog
    {
        public List<AuthenticationProperties> Items { get; } = [];
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now = _now.Add(by);
    }

    /// <summary>Fake provider: records the challenge and redirects to a fake authorize URL.</summary>
    private sealed class CapturingHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly ChallengeLog _log;

        public CapturingHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ChallengeLog log)
            : base(options, logger, encoder)
        {
            _log = log;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
            Task.FromResult(AuthenticateResult.NoResult());

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            _log.Items.Add(properties);
            Response.Redirect("https://idp.test/authorize");
            return Task.CompletedTask;
        }
    }
}
