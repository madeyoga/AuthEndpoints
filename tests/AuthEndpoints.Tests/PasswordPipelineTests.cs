using System.Diagnostics;
using System.Net;
using System.Text.Json;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.Tests;

public class PasswordPipelineTests
{
    private const double TimingBoundMilliseconds = 50;

    [Fact]
    public async Task ParameterlessLogin_MatchesPasswordPipelineParity()
    {
        await using var host = await SignInHost.StartAsync(o =>
        {
            o.MaxFailedAccessAttempts = 3;
            o.Map = app => app.MapPasswordEndpoints<TestAppUser>();
        });

        var email = Email("lockout");
        await host.SeedAsync(email);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var wrong = await host.Client.PostAsync("/login", new { email, password = "wrong-password" });
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
            Assert.Contains("Invalid credentials", await wrong.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        Assert.True(await IsLockedOutAsync(host.App, email));
        var locked = await host.Client.PostAsync("/login", new { email, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, locked.StatusCode);

        var factor = Email("factor");
        await host.SeedAsync(factor, twoFactor: true);
        var missing = await host.Client.PostAsync("/login", new { email = factor, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal("RequiresTwoFactor", await TitleAsync(missing));
        Assert.Equal(0, await AccessFailedCountAsync(host.App, factor));

        var wrongTotp = await host.Client.PostAsync(
            "/login",
            new { email = factor, password = TestHelpers.DefaultPassword, twoFactorCode = WrongTotp(await host.AuthenticatorKeyAsync(factor)) });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongTotp.StatusCode);
        Assert.Equal("Unauthorized", await TitleAsync(wrongTotp));
        Assert.Equal(1, await AccessFailedCountAsync(host.App, factor));

        var recoveryUser = Email("recovery");
        await host.SeedAsync(recoveryUser, twoFactor: true);
        var code = await RecoveryCodeAsync(host.App, recoveryUser);
        var before = await RecoveryCodeCountAsync(host.App, recoveryUser);
        var spent = await host.Client.PostAsync(
            "/login",
            new { email = recoveryUser, password = TestHelpers.DefaultPassword, twoFactorRecoveryCode = code });
        Assert.Equal(HttpStatusCode.OK, spent.StatusCode);
        Assert.True(HasApplicationCookie(spent));
        Assert.Equal(before - 1, await RecoveryCodeCountAsync(host.App, recoveryUser));
        var again = await host.Client.PostAsync(
            "/login",
            new { email = recoveryUser, password = TestHelpers.DefaultPassword, twoFactorRecoveryCode = code });
        Assert.Equal(HttpStatusCode.Unauthorized, again.StatusCode);
        Assert.Equal(before - 1, await RecoveryCodeCountAsync(host.App, recoveryUser));
    }

    [Fact]
    public async Task WrongRecoveryCode_CountsTowardLockout_AndStaysUnused()
    {
        await using var host = await SignInHost.StartAsync(o => o.Map = app => app.MapPasswordSignInEndpoints<TestAppUser>());
        var email = Email("bad-recovery");
        await host.SeedAsync(email, twoFactor: true);
        var code = await RecoveryCodeAsync(host.App, email);
        var before = await RecoveryCodeCountAsync(host.App, email);

        var wrong = await host.Client.PostAsync(
            "/login",
            new { email, password = TestHelpers.DefaultPassword, twoFactorRecoveryCode = "not-a-recovery-code" });
        var wrongBody = await wrong.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Contains("Invalid credentials", wrongBody, StringComparison.Ordinal);
        Assert.DoesNotContain("Recovery code redemption failed", wrongBody, StringComparison.Ordinal);
        Assert.Equal(1, await AccessFailedCountAsync(host.App, email));
        Assert.Equal(before, await RecoveryCodeCountAsync(host.App, email));

        var ok = await host.Client.PostAsync(
            "/login",
            new { email, password = TestHelpers.DefaultPassword, twoFactorRecoveryCode = code });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(0, await AccessFailedCountAsync(host.App, email));
    }

    [Fact]
    public async Task RememberClientCookie_SkipsTotpOnNextCookieLogin()
    {
        await using var host = await SignInHost.StartAsync(o => o.Map = app => app.MapPasswordSignInEndpoints<TestAppUser>());
        var email = Email("remember");
        await host.SeedAsync(email, twoFactor: true);
        var code = TotpHelper.GenerateCode(await host.AuthenticatorKeyAsync(email));

        var first = await host.Client.PostAsync(
            "/login?useSessionCookies=false",
            new { email, password = TestHelpers.DefaultPassword, twoFactorCode = code });
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.True(HasApplicationCookie(first));

        var second = await host.Client.PostAsync("/login", new { email, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.False((await second.Content.ReadAsStringAsync()).Contains("RequiresTwoFactor", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RequireConfirmedAccount_RejectsUnconfirmedUser()
    {
        await using var host = await SignInHost.StartAsync(o =>
        {
            o.RequireConfirmedAccount = true;
            o.Map = app => app.MapPasswordEndpoints<TestAppUser>();
        });

        var unconfirmed = Email("unconfirmed");
        await host.SeedAsync(unconfirmed, confirmed: false);
        var rejected = await host.Client.PostAsync("/login", new { email = unconfirmed, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        Assert.Equal("Unauthorized", await TitleAsync(rejected));
        Assert.Equal(0, await AccessFailedCountAsync(host.App, unconfirmed));

        var confirmed = Email("confirmed");
        await host.SeedAsync(confirmed);
        var accepted = await host.Client.PostAsync("/login", new { email = confirmed, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.True(HasApplicationCookie(accepted));
    }

    [Fact]
    public async Task Create_WrongSecondFactor_CountsTowardLockout_AndUsesGenericBody()
    {
        await using var host = await SignInHost.StartAsync(o => o.Map = app => app.MapGroup("/auth").MapJwtAuthEndpoints<TestAppUser>());

        var missingBody = await host.Client.PostAsync("/auth/create", new { email = "", password = "" });
        Assert.Equal(HttpStatusCode.BadRequest, missingBody.StatusCode);
        Assert.Contains("invalid_request", await missingBody.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var email = Email("create");
        await host.SeedAsync(email, twoFactor: true);
        var key = await host.AuthenticatorKeyAsync(email);

        var missingFactor = await host.Client.PostAsync("/auth/create", new { email, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, missingFactor.StatusCode);
        using (var doc = JsonDocument.Parse(await missingFactor.Content.ReadAsStringAsync()))
        {
            Assert.Equal("RequiresTwoFactor", doc.RootElement.GetProperty("title").GetString());
            Assert.True(doc.RootElement.GetProperty("requiresTwoFactor").GetBoolean());
        }

        Assert.Equal(0, await AccessFailedCountAsync(host.App, email));

        var wrongTotp = await host.Client.PostAsync(
            "/auth/create",
            new { email, password = TestHelpers.DefaultPassword, twoFactorCode = WrongTotp(key) });
        var wrongTotpBody = await wrongTotp.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, wrongTotp.StatusCode);
        Assert.Contains("Invalid credentials", wrongTotpBody, StringComparison.Ordinal);
        Assert.DoesNotContain("Invalid two factor code", wrongTotpBody, StringComparison.Ordinal);
        Assert.Equal(1, await AccessFailedCountAsync(host.App, email));

        var wrongRecovery = await host.Client.PostAsync(
            "/auth/create",
            new { email, password = TestHelpers.DefaultPassword, twoFactorRecoveryCode = "not-a-recovery-code" });
        var wrongRecoveryBody = await wrongRecovery.Content.ReadAsStringAsync();
        Assert.Contains("Invalid credentials", wrongRecoveryBody, StringComparison.Ordinal);
        Assert.DoesNotContain("Recovery code redemption failed", wrongRecoveryBody, StringComparison.Ordinal);
        Assert.Equal(2, await AccessFailedCountAsync(host.App, email));

        var ok = await host.Client.PostAsync(
            "/auth/create",
            new { email, password = TestHelpers.DefaultPassword, twoFactorCode = TotpHelper.GenerateCode(key) });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        using var success = JsonDocument.Parse(await ok.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrWhiteSpace(TestHelpers.TryGetString(success.RootElement, "accessToken", "AccessToken")));
        Assert.Equal(0, await AccessFailedCountAsync(host.App, email));
    }

    [Fact]
    public async Task Create_CustomAuthenticator_IsStillConsulted()
    {
        await using var host = await SignInHost.StartAsync(o =>
        {
            o.ConfigureServices = services =>
            {
                services.Replace(ServiceDescriptor.Scoped<IAuthenticator<TestAppUser>, MagicAuthenticator>());
            };
            o.Map = app => app.MapJwtPasswordEndpoints<TestAppUser>();
        });

        var email = Email("magic");
        await host.SeedAsync(email);
        var real = await host.Client.PostAsync("/create", new { email, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, real.StatusCode);

        var magic = await host.Client.PostAsync("/create", new { email, password = MagicAuthenticator.Password });
        Assert.Equal(HttpStatusCode.OK, magic.StatusCode);
        using var doc = JsonDocument.Parse(await magic.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrWhiteSpace(TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken")));
    }

    [Fact]
    public async Task UnknownUser_MatchesKnownUserTiming_OnLoginAndCreate()
    {
        await using var host = await SignInHost.StartAsync(o =>
        {
            o.MaxFailedAccessAttempts = 100;
            o.Map = app =>
            {
                app.MapPasswordEndpoints<TestAppUser>();
                app.MapGroup("/jwt").MapJwtPasswordEndpoints<TestAppUser>();
            };
        });

        var known = Email("timing");
        await host.SeedAsync(known);
        await AssertTimingAsync(host, "/login", known);
        await AssertTimingAsync(host, "/jwt/create", known);
    }

    [Fact]
    public async Task LoginAndCreate_FailuresShareOneLockout()
    {
        await using var host = await SignInHost.StartAsync(o =>
        {
            o.MaxFailedAccessAttempts = 3;
            o.Map = app =>
            {
                app.MapPasswordEndpoints<TestAppUser>();
                app.MapGroup("/jwt").MapJwtPasswordEndpoints<TestAppUser>();
            };
        });

        var email = Email("shared-lockout");
        await host.SeedAsync(email);

        Assert.Equal(HttpStatusCode.Unauthorized, (await PostPasswordAsync(host, "/login", email)).StatusCode);
        Assert.Equal(1, await AccessFailedCountAsync(host.App, email));
        Assert.False(await IsLockedOutAsync(host.App, email));

        Assert.Equal(HttpStatusCode.Unauthorized, (await PostPasswordAsync(host, "/jwt/create", email)).StatusCode);
        Assert.Equal(2, await AccessFailedCountAsync(host.App, email));

        Assert.Equal(HttpStatusCode.Unauthorized, (await PostPasswordAsync(host, "/login", email)).StatusCode);
        Assert.True(await IsLockedOutAsync(host.App, email));

        var lockedLogin = await host.Client.PostAsync("/login", new { email, password = TestHelpers.DefaultPassword });
        var lockedCreate = await host.Client.PostAsync("/jwt/create", new { email, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, lockedLogin.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, lockedCreate.StatusCode);
        Assert.Contains("Invalid credentials", await lockedLogin.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Contains("Invalid credentials", await lockedCreate.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.True(await IsLockedOutAsync(host.App, email));
    }

    [Fact]
    public async Task UnknownUser_DummyHashReceivesThrowawayUser_OnLoginAndCreate()
    {
        UserReadingHasher.Reset();
        await using var host = await SignInHost.StartAsync(o =>
        {
            o.ConfigureServices = services =>
            {
                services.Replace(ServiceDescriptor.Scoped<IPasswordHasher<TestAppUser>, UserReadingHasher>());
            };
            o.Map = app =>
            {
                app.MapPasswordEndpoints<TestAppUser>();
                app.MapGroup("/jwt").MapJwtPasswordEndpoints<TestAppUser>();
            };
        });

        var login = await PostPasswordAsync(host, "/login", Email("hash-login"));
        var create = await PostPasswordAsync(host, "/jwt/create", Email("hash-create"));
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, create.StatusCode);
        Assert.Contains("Invalid credentials", await login.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Contains("Invalid credentials", await create.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var ids = UserReadingHasher.Snapshot();
        Assert.Contains(PasswordHashTiming<TestAppUser>.DummyUserId, ids);
        Assert.DoesNotContain(ids, id => string.IsNullOrEmpty(id));
        Assert.True(ids.Count >= 2, $"Expected a hasher call for login and create, saw {ids.Count}.");
    }

    private static async Task AssertTimingAsync(SignInHost host, string url, string knownEmail)
    {
        const int warmup = 4;
        const int samples = 11;
        for (var i = 0; i < warmup; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await PostPasswordAsync(host, url, knownEmail)).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await PostPasswordAsync(host, url, Email("warm"))).StatusCode);
        }

        var known = new List<double>(samples);
        var unknown = new List<double>(samples);
        for (var i = 0; i < samples; i++)
        {
            known.Add(await ElapsedAsync(host, url, knownEmail));
            unknown.Add(await ElapsedAsync(host, url, Email("miss")));
        }

        var knownMedian = Median(known);
        var unknownMedian = Median(unknown);
        var delta = Math.Abs(knownMedian - unknownMedian);
        Assert.True(
            delta <= TimingBoundMilliseconds,
            $"{url} warmed median delta {delta:F1}ms (known {knownMedian:F1}ms, unknown {unknownMedian:F1}ms) exceeded {TimingBoundMilliseconds}ms.");
    }

    private static async Task<double> ElapsedAsync(SignInHost host, string url, string email)
    {
        var watch = Stopwatch.StartNew();
        var response = await PostPasswordAsync(host, url, email);
        watch.Stop();
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        return watch.Elapsed.TotalMilliseconds;
    }

    private static Task<HttpResponseMessage> PostPasswordAsync(SignInHost host, string url, string email)
    {
        return host.Client.PostAsync(url, new { email, password = "wrong-password" });
    }

    private static double Median(List<double> samples)
    {
        var sorted = samples.OrderBy(value => value).ToArray();
        var mid = sorted.Length / 2;
        return sorted.Length % 2 == 1
            ? sorted[mid]
            : (sorted[mid - 1] + sorted[mid]) / 2;
    }

    private static async Task<bool> IsLockedOutAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await users.FindByEmailAsync(email);
        Assert.NotNull(user);
        return await users.IsLockedOutAsync(user);
    }

    private static async Task<int> AccessFailedCountAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await users.FindByEmailAsync(email);
        Assert.NotNull(user);
        return await users.GetAccessFailedCountAsync(user);
    }

    private static async Task<string> RecoveryCodeAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await users.FindByEmailAsync(email);
        var codes = await users.GenerateNewTwoFactorRecoveryCodesAsync(user!, 5);
        return codes!.First();
    }

    private static async Task<int> RecoveryCodeCountAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await users.FindByEmailAsync(email);
        return await users.CountRecoveryCodesAsync(user!);
    }

    private static async Task<string?> TitleAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("title").GetString();
    }

    private static bool HasApplicationCookie(HttpResponseMessage response)
    {
        return response.Headers.TryGetValues("Set-Cookie", out var values)
            && values.Any(value => value.Contains(".AspNetCore.Identity.Application", StringComparison.Ordinal));
    }

    private static string WrongTotp(string key)
    {
        var current = TotpHelper.GenerateCode(key);
        return current == "000000" ? "111111" : "000000";
    }

    private static string Email(string label) => $"{label}-{Guid.NewGuid():N}@test.local";

    private sealed class MagicAuthenticator : IAuthenticator<TestAppUser>
    {
        public const string Password = "magic-password";

        private readonly UserManager<TestAppUser> _users;

        public MagicAuthenticator(UserManager<TestAppUser> users)
        {
            _users = users;
        }

        public async Task<AuthenticationResult<TestAppUser>> AuthenticateAsync(string username, string password)
        {
            var user = await _users.FindByEmailAsync(username);
            if (user is null || password != Password)
            {
                return AuthenticationResult<TestAppUser>.Failed(new AuthenticationError
                {
                    Code = "invalid_credentials",
                    Description = "Invalid credentials.",
                });
            }

            return AuthenticationResult<TestAppUser>.Success(user);
        }
    }

    private sealed class UserReadingHasher : PasswordHasher<TestAppUser>
    {
        private static readonly object Gate = new();
        private static readonly List<string> SeenIds = [];

        public static void Reset()
        {
            lock (Gate)
            {
                SeenIds.Clear();
            }
        }

        public static IReadOnlyList<string> Snapshot()
        {
            lock (Gate)
            {
                return SeenIds.ToArray();
            }
        }

        public override string HashPassword(TestAppUser user, string password)
        {
            Note(user);
            return base.HashPassword(user, password);
        }

        public override PasswordVerificationResult VerifyHashedPassword(
            TestAppUser user,
            string hashedPassword,
            string providedPassword)
        {
            Note(user);
            return base.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }

        private static void Note(TestAppUser user)
        {
            var id = user.Id;
            lock (Gate)
            {
                SeenIds.Add(id);
            }
        }
    }
}
