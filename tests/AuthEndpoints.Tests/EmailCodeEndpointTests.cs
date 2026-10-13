using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.ReAuth;
using EmailCodeEntity = AuthEndpoints.EmailCode.EmailCodeEntry;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests;

public partial class EmailCodeEndpointTests
{
    [Fact]
    public async Task Send_SameStatusAndBody_ForKnownUnknownLockedCooldownRejectAndSenderFailure()
    {
        var sender = new SelectiveEmailCodeSender();
        await using var host = await EmailCodeHost.StartAsync(
            configure: options => options.UnconfirmedAccounts = EmailCodeUnconfirmedAccounts.Reject,
            sender: sender);

        var known = UniqueEmail("known");
        var unknown = UniqueEmail("unknown");
        var lockedEmail = UniqueEmail("locked");
        var rejected = UniqueEmail("rejected");
        var throwing = UniqueEmail("throw");

        await SeedAsync(host.App, known);
        await SeedAsync(host.App, lockedEmail);
        await LockAsync(host.App, lockedEmail);
        await SeedAsync(host.App, rejected, confirmed: false);
        await SeedAsync(host.App, throwing);

        var first = await PostAsync(host.Client, "/identity/emailCode/send", new { email = known });
        var unknownResponse = await PostAsync(host.Client, "/identity/emailCode/send", new { email = unknown });
        var lockedResponse = await PostAsync(host.Client, "/identity/emailCode/send", new { email = lockedEmail });
        var cooled = await PostAsync(host.Client, "/identity/emailCode/send", new { email = known });
        var rejectedResponse = await PostAsync(host.Client, "/identity/emailCode/send", new { email = rejected });
        var threw = await PostAsync(host.Client, "/identity/emailCode/send", new { email = throwing });

        var body = await first.Content.ReadAsStringAsync();
        var headers = StableHeaders(first);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        foreach (var response in new[] { unknownResponse, lockedResponse, cooled, rejectedResponse, threw })
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(body, await response.Content.ReadAsStringAsync());
            Assert.Equal(headers, StableHeaders(response));
        }

        using var doc = JsonDocument.Parse(body);
        Assert.Equal(600, doc.RootElement.GetProperty("expiresInSeconds").GetInt32());
        Assert.Equal(60, doc.RootElement.GetProperty("resendAfterSeconds").GetInt32());

        Assert.Single(Codes(sender.Inner, known));
        Assert.Empty(Codes(sender.Inner, unknown));
        Assert.Empty(Codes(sender.Inner, lockedEmail));
        Assert.Empty(Codes(sender.Inner, rejected));
        Assert.Single(Codes(sender.Inner, throwing));

        var knownRows = await RowsAsync(host.App, known);
        Assert.Single(knownRows);
        Assert.NotNull(knownRows[0].UserId);
        Assert.Equal(EmailCodeHasher.HashCode(knownRows[0].Id, Codes(sender.Inner, known).Single()), knownRows[0].CodeHash);

        Assert.Null((await RowsAsync(host.App, unknown)).Single().UserId);
        Assert.Null((await RowsAsync(host.App, lockedEmail)).Single().UserId);
        Assert.Null((await RowsAsync(host.App, rejected)).Single().UserId);
        Assert.Null((await RowsAsync(host.App, throwing)).Single().ConsumedAt);
    }

    [Fact]
    public async Task Send_MalformedEmail_Is400_AndSixthSendPerIp_Is429()
    {
        await using var malformedHost = await EmailCodeHost.StartAsync();
        var malformed = await PostAsync(malformedHost.Client, "/identity/emailCode/send", new { email = "not-an-email" });
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        using (var doc = JsonDocument.Parse(await malformed.Content.ReadAsStringAsync()))
        {
            Assert.True(doc.RootElement.GetProperty("errors").TryGetProperty("InvalidEmail", out _));
        }

        await using var limited = await EmailCodeHost.StartAsync(options => options.SendsPerIpPerMinute = 5);
        for (var i = 0; i < 5; i++)
        {
            var ok = await PostAsync(limited.Client, "/identity/emailCode/send", new { email = UniqueEmail("ip") });
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        var blocked = await PostAsync(limited.Client, "/identity/emailCode/send", new { email = UniqueEmail("ip") });
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.True(string.IsNullOrEmpty(await blocked.Content.ReadAsStringAsync()));
    }

    [Fact]
    public async Task Send_CooldownThenResend_InvalidatesThePreviousCode()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("cooldown");
        await SeedAsync(host.App, email);

        Assert.Equal(HttpStatusCode.OK, (await PostAsync(host.Client, "/identity/emailCode/send", new { email })).StatusCode);
        var first = Codes(host.Mail, email).Single();
        var cooled = await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        Assert.Equal(HttpStatusCode.OK, cooled.StatusCode);
        Assert.Single(Codes(host.Mail, email));

        host.Clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(host.Client, "/identity/emailCode/send", new { email })).StatusCode);
        var codes = Codes(host.Mail, email);
        Assert.Equal(2, codes.Count);
        var second = codes[1];

        var old = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = first });
        Assert.Equal(HttpStatusCode.Unauthorized, old.StatusCode);
        Assert.Equal("Unauthorized", await ProblemTitleAsync(old));

        var newest = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = second });
        Assert.Equal(HttpStatusCode.OK, newest.StatusCode);
    }

    [Fact]
    public async Task Send_OverPerEmailCap_Returns200WithoutMail()
    {
        await using var host = await EmailCodeHost.StartAsync(options =>
        {
            options.ResendCooldown = TimeSpan.Zero;
            options.MaxSendsPerEmail = 2;
        });
        var email = UniqueEmail("cap");
        await SeedAsync(host.App, email);

        string? body = null;
        for (var i = 0; i < 2; i++)
        {
            var response = await PostAsync(host.Client, "/identity/emailCode/send", new { email });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            body ??= await response.Content.ReadAsStringAsync();
        }

        var capped = await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        Assert.Equal(HttpStatusCode.OK, capped.StatusCode);
        Assert.Equal(body, await capped.Content.ReadAsStringAsync());
        Assert.Equal(2, Codes(host.Mail, email).Count);
    }

    [Fact]
    public async Task Verify_Succeeds_ForCookieBearerAndJwt()
    {
        var email = UniqueEmail("cookie");
        await using (var host = await EmailCodeHost.StartAsync())
        {
            await SeedAsync(host.App, email);
            await PostAsync(host.Client, "/identity/emailCode/send", new { email });
            var jar = new CookieJar();
            var response = await PostAsync(
                host.Client,
                "/identity/emailCode/verify?useSessionCookies=true",
                new { email, code = Codes(host.Mail, email).Single() },
                jar);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains(".AspNetCore.Identity.Application", SetCookie(response), StringComparison.Ordinal);
            var info = await GetAsync(host.Client, "/identity/manage/info", jar);
            Assert.Equal(HttpStatusCode.OK, info.StatusCode);
            Assert.Contains(email, await info.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        email = UniqueEmail("bearer");
        await using (var host = await EmailCodeHost.StartAsync())
        {
            await SeedAsync(host.App, email);
            await PostAsync(host.Client, "/identity/emailCode/send", new { email });
            var response = await PostAsync(
                host.Client,
                "/identity/emailCode/verify",
                new { email, code = Codes(host.Mail, email).Single() });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.False(string.IsNullOrWhiteSpace(TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken")));
        }

        email = UniqueEmail("jwt");
        await using (var host = await EmailCodeHost.StartAsync(jwt: true))
        {
            await SeedAsync(host.App, email);
            await PostAsync(host.Client, "/identity/emailCode/send", new { email });
            var response = await PostAsync(
                host.Client,
                "/identity/emailCode/verify",
                new { email, code = Codes(host.Mail, email).Single() });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.False(string.IsNullOrWhiteSpace(TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken")));
            Assert.Contains(RefreshTokenCookieWriter.CookieName, SetCookie(response), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Facade_DisabledOmitsRoutes_EnabledMapsBothUnderIdentityPath()
    {
        Assert.False(new AuthEndpointsOptions().EmailCode.Enabled);

        await using (var disabled = await StartFacadeAsync(enabled: false))
        {
            using var client = disabled.GetTestClient();
            Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync("/identity/emailCode/send", new { email = "a@x.com" })).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync("/identity/emailCode/verify", new { email = "a@x.com", code = "000000" })).StatusCode);
        }

        await using (var enabled = await StartFacadeAsync(enabled: true, identityPath: "/accounts"))
        {
            using var client = enabled.GetTestClient();
            var send = await client.PostAsJsonAsync("/accounts/emailCode/send", new { email = "not-an-email" });
            Assert.Equal(HttpStatusCode.BadRequest, send.StatusCode);
            using (var doc = JsonDocument.Parse(await send.Content.ReadAsStringAsync()))
            {
                Assert.True(doc.RootElement.GetProperty("errors").TryGetProperty("InvalidEmail", out _));
            }

            var verify = await client.PostAsJsonAsync("/accounts/emailCode/verify", new { token = "abc" });
            Assert.Equal(HttpStatusCode.BadRequest, verify.StatusCode);
            using (var doc = JsonDocument.Parse(await verify.Content.ReadAsStringAsync()))
            {
                Assert.True(doc.RootElement.GetProperty("errors").TryGetProperty("InvalidEmailCodeRequest", out _));
            }

            Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync("/identity/emailCode/send", new { email = "not-an-email" })).StatusCode);
        }
    }

    [Fact]
    public async Task Verify_FifthWrongCode_KillsTheRow()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("attempts");
        await SeedAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();
        var wrong = WrongCode(code);

        for (var i = 0; i < 5; i++)
        {
            var failed = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = wrong });
            Assert.Equal(HttpStatusCode.Unauthorized, failed.StatusCode);
            Assert.Equal("Unauthorized", await ProblemTitleAsync(failed));
        }

        var right = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
        Assert.Equal(HttpStatusCode.Unauthorized, right.StatusCode);
        var row = (await RowsAsync(host.App, email)).Single();
        Assert.Equal(5, row.Attempts);
        Assert.Null(row.ConsumedAt);
    }

    [Fact]
    public async Task Verify_ReplayFails_AndParallelConsumeAllowsOne()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("race");
        await SeedAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();

        using var clientA = host.App.GetTestClient();
        using var clientB = host.App.GetTestClient();
        var first = PostAsync(clientA, "/identity/emailCode/verify", new { email, code });
        var second = PostAsync(clientB, "/identity/emailCode/verify", new { email, code });
        var results = await Task.WhenAll(first, second);
        Assert.Equal(1, results.Count(response => response.StatusCode == HttpStatusCode.OK));
        Assert.Equal(1, results.Count(response => response.StatusCode == HttpStatusCode.Unauthorized));

        var replay = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal("Unauthorized", await ProblemTitleAsync(replay));
        Assert.NotNull((await RowsAsync(host.App, email)).Single().ConsumedAt);
    }

    [Fact]
    public async Task Verify_ExpiredCode_FailsWithoutConsuming()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("expired");
        await SeedAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();

        host.Clock.Advance(TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(1));
        var response = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null((await RowsAsync(host.App, email)).Single().ConsumedAt);
    }

    [Fact]
    public async Task Verify_StampChangeAndEmailChange_ConsumeAndFail()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("stamp");
        var user = await SeedAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();

        using (var scope = host.App.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var fresh = await userManager.FindByIdAsync(user.Id);
            var token = await userManager.GeneratePasswordResetTokenAsync(fresh!);
            var reset = await userManager.ResetPasswordAsync(fresh!, token, "NewPass1!");
            Assert.True(reset.Succeeded, string.Join("; ", reset.Errors.Select(error => error.Description)));
        }

        var stamped = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
        Assert.Equal(HttpStatusCode.Unauthorized, stamped.StatusCode);
        Assert.NotNull((await RowsAsync(host.App, email)).Single(row => row.CodeHash == EmailCodeHasher.HashCode(row.Id, code)).ConsumedAt);

        var moved = UniqueEmail("moved");
        await SeedAsync(host.App, moved);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email = moved });
        var movedCode = Codes(host.Mail, moved).Single();
        using (var scope = host.App.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var fresh = await userManager.FindByEmailAsync(moved);
            var set = await userManager.SetEmailAsync(fresh!, UniqueEmail("other"));
            Assert.True(set.Succeeded, string.Join("; ", set.Errors.Select(error => error.Description)));
        }

        var changed = await PostAsync(host.Client, "/identity/emailCode/verify", new { email = moved, code = movedCode });
        Assert.Equal(HttpStatusCode.Unauthorized, changed.StatusCode);
        Assert.NotNull((await RowsAsync(host.App, moved)).Single().ConsumedAt);
    }

    [Fact]
    public async Task Verify_TwoFactor_RequiresProof_AcceptsTotpOrRecovery_AndWrongTotpCounts()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("totp");
        await SeedAsync(host.App, email, twoFactor: true);
        var key = await AuthenticatorKeyAsync(host.App, email);

        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();
        var missing = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal("RequiresTwoFactor", await ProblemTitleAsync(missing));
        Assert.Equal("Two-factor authentication is required.", await ProblemDetailAsync(missing));
        Assert.Null((await RowsAsync(host.App, email)).Single().ConsumedAt);

        var wrong = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code, twoFactorCode = WrongCode(TotpHelper.GenerateCode(key)) });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal("Unauthorized", await ProblemTitleAsync(wrong));
        Assert.Equal(1, (await RowsAsync(host.App, email)).Single().Attempts);
        Assert.Equal(1, await AccessFailedCountAsync(host.App, email));
        Assert.Null((await RowsAsync(host.App, email)).Single().ConsumedAt);

        var totp = TotpHelper.GenerateCode(key);
        var accepted = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code, twoFactorCode = totp });
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);

        var recoveryEmail = UniqueEmail("recovery");
        await SeedAsync(host.App, recoveryEmail, twoFactor: true);
        var recoveryCode = await RecoveryCodeAsync(host.App, recoveryEmail);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email = recoveryEmail });
        var recoverySignIn = Codes(host.Mail, recoveryEmail).Single();
        var redeemed = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email = recoveryEmail, code = recoverySignIn, twoFactorRecoveryCode = recoveryCode });
        Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
        Assert.False(await RecoveryCodeStillValidAsync(host.App, recoveryEmail, recoveryCode));
    }

    [Fact]
    public async Task Verify_RequireTwoFactorFalse_AllowsCodeAlone()
    {
        await using var host = await EmailCodeHost.StartAsync(options => options.RequireTwoFactor = false);
        var email = UniqueEmail("notwofactor");
        await SeedAsync(host.App, email, twoFactor: true);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var response = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code = Codes(host.Mail, email).Single() });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Verify_Lockout_StopsMailAndKeepsTheRightCodeUnconsumed()
    {
        await using var host = await EmailCodeHost.StartAsync(
            options =>
            {
                options.MaxAttempts = 10;
                options.ResendCooldown = TimeSpan.Zero;
            },
            identity => identity.Lockout.MaxFailedAccessAttempts = 3);
        var email = UniqueEmail("lockout");
        await SeedAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();
        var wrong = WrongCode(code);

        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(
                HttpStatusCode.Unauthorized,
                (await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = wrong })).StatusCode);
        }

        Assert.True(await IsLockedOutAsync(host.App, email));
        var right = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
        Assert.Equal(HttpStatusCode.Unauthorized, right.StatusCode);
        var issued = (await RowsAsync(host.App, email)).Single();
        Assert.Null(issued.ConsumedAt);
        Assert.Equal(3, issued.Attempts);

        var again = await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Single(Codes(host.Mail, email));
        var replay = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task Verify_UnconfirmedWithoutCredentials_ConfirmsAndSignsIn()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("bare");
        var user = await SeedAsync(host.App, email, password: null, confirmed: false);
        var stamp = await StampAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var response = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code = Codes(host.Mail, email).Single() });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await IsConfirmedAsync(host.App, email));
        Assert.Equal(stamp, await StampAsync(host.App, email));
        Assert.False(string.IsNullOrEmpty(user.Id));
    }

    [Fact]
    public async Task Verify_UnconfirmedWithCredentials_ResetsOrRejects()
    {
        await using (var host = await EmailCodeHost.StartAsync())
        {
            var email = UniqueEmail("reset");
            await SeedAsync(host.App, email, confirmed: false);
            await AddLoginAsync(host.App, email);
            await AddPasskeyAsync(host.App, email);
            var stamp = await StampAsync(host.App, email);
            await PostAsync(host.Client, "/identity/emailCode/send", new { email });
            var response = await PostAsync(
                host.Client,
                "/identity/emailCode/verify",
                new { email, code = Codes(host.Mail, email).Single() });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(await IsConfirmedAsync(host.App, email));
            Assert.False(await HasPasswordAsync(host.App, email));
            Assert.Empty(await LoginsAsync(host.App, email));
            Assert.Empty(await PasskeysAsync(host.App, email));
            Assert.NotEqual(stamp, await StampAsync(host.App, email));
        }

        await using (var host = await EmailCodeHost.StartAsync(
            options => options.UnconfirmedAccounts = EmailCodeUnconfirmedAccounts.Reject))
        {
            var email = UniqueEmail("reject");
            await SeedAsync(host.App, email, confirmed: false);
            await PostAsync(host.Client, "/identity/emailCode/send", new { email });
            Assert.Empty(Codes(host.Mail, email));
            Assert.Null((await RowsAsync(host.App, email)).Single().UserId);

            string code;
            host.Clock.Advance(TimeSpan.FromSeconds(61));
            using (var scope = host.App.Services.CreateScope())
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
                var store = scope.ServiceProvider.GetRequiredService<IEmailCodeStore>();
                var user = await userManager.FindByEmailAsync(email);
                var issued = await store.IssueAsync(
                    email,
                    user!.Id,
                    await userManager.GetSecurityStampAsync(user),
                    EmailCodeRowPurpose.SignIn);
                Assert.False(issued.Suppressed);
                code = issued.Code;
            }

            var response = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("Unauthorized", await ProblemTitleAsync(response));
            Assert.NotNull((await RowsAsync(host.App, email)).Single(row => row.UserId != null).ConsumedAt);
            Assert.False(await IsConfirmedAsync(host.App, email));
            Assert.True(await HasPasswordAsync(host.App, email));
        }
    }

    [Fact]
    public async Task Verify_UnknownEmail_DoesNotSignUp()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("nosignup");
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(host.Client, "/identity/emailCode/send", new { email })).StatusCode);
        Assert.Empty(Codes(host.Mail, email));
        var response = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = "000000" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Unauthorized", await ProblemTitleAsync(response));
        Assert.Equal(1, (await RowsAsync(host.App, email)).Single().Attempts);
        using var scope = host.App.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        Assert.Null(await userManager.FindByEmailAsync(email));
    }

    [Fact]
    public async Task AllowSignUp_OffRejectsTheCorrectCode_OnCreatesAConfirmedUser_AndExistingUsersStayOnTheSignInPath()
    {
        await using (var off = await EmailCodeHost.StartAsync())
        {
            var email = UniqueEmail("signup-off");
            await PostAsync(off.Client, "/identity/emailCode/send", new { email });
            Assert.Empty(Codes(off.Mail, email));
            Assert.Null((await RowsAsync(off.App, email)).Single().SignupEmail);
            string code;
            off.Clock.Advance(TimeSpan.FromSeconds(61));
            using (var scope = off.App.Services.CreateScope())
            {
                var store = scope.ServiceProvider.GetRequiredService<IEmailCodeStore>();
                var issued = await store.IssueAsync(email, null, null, EmailCodeRowPurpose.SignIn);
                Assert.False(issued.Suppressed);
                code = issued.Code;
            }

            var rejected = await PostAsync(off.Client, "/identity/emailCode/verify", new { email, code });
            Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
            Assert.Equal("Unauthorized", await ProblemTitleAsync(rejected));
            Assert.Equal(0, await CountUsersAsync(off.App, email));
        }

        await using var on = await EmailCodeHost.StartAsync(options => options.AllowSignUp = true, captureLogs: true);
        var missed = UniqueEmail("signup-miss");
        await PostAsync(on.Client, "/identity/emailCode/send", new { email = missed });
        var missedMail = MailFor(on.Mail, missed);
        var missedVerify = await PostAsync(
            on.Client,
            "/identity/emailCode/verify",
            new { email = missed, code = WrongCode(missedMail.Body) });
        Assert.Equal(HttpStatusCode.Unauthorized, missedVerify.StatusCode);
        Assert.Equal(0, await CountUsersAsync(on.App, missed));
        Assert.Equal(1, (await RowsAsync(on.App, missed)).Single().Attempts);

        var known = UniqueEmail("signup-known");
        var unknown = UniqueEmail("signup-new");
        await SeedAsync(on.App, known);
        var knownId = await UserIdAsync(on.App, known);
        var knownSend = await PostAsync(on.Client, "/identity/emailCode/send", new { email = known });
        var unknownSend = await PostAsync(on.Client, "/identity/emailCode/send", new { email = unknown });
        Assert.Equal(HttpStatusCode.OK, knownSend.StatusCode);
        Assert.Equal(await knownSend.Content.ReadAsStringAsync(), await unknownSend.Content.ReadAsStringAsync());
        Assert.Equal(EmailCodePurpose.SignIn, MailFor(on.Mail, known).Purpose);
        Assert.Null(MailFor(on.Mail, known).LinkUrl);
        var unknownMail = MailFor(on.Mail, unknown);
        Assert.Equal(EmailCodePurpose.SignUp, unknownMail.Purpose);
        Assert.Null(unknownMail.LinkUrl);
        var unknownRow = (await RowsAsync(on.App, unknown)).Single();
        Assert.Equal(unknown, unknownRow.SignupEmail);
        Assert.Null(unknownRow.UserId);
        Assert.Null((await RowsAsync(on.App, known)).Single().SignupEmail);

        var created = await PostAsync(
            on.Client,
            "/identity/emailCode/verify",
            new { email = unknown, code = unknownMail.Body });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        using (var doc = JsonDocument.Parse(await created.Content.ReadAsStringAsync()))
        {
            Assert.False(string.IsNullOrWhiteSpace(TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken")));
        }

        Assert.Equal(1, await CountUsersAsync(on.App, unknown));
        Assert.True(await IsConfirmedAsync(on.App, unknown));
        Assert.False(await HasPasswordAsync(on.App, unknown));
        Assert.DoesNotContain(on.Mail.Snapshot(), item => item.Kind == "confirm" && item.Email == unknown);
        Assert.Contains(on.Logs.Messages, message => message.Contains("SignedUp", StringComparison.Ordinal));
        foreach (var message in on.Logs.Messages)
        {
            Assert.DoesNotContain(unknown, message, StringComparison.Ordinal);
            Assert.DoesNotContain(unknownMail.Body, message, StringComparison.Ordinal);
        }

        var existing = await PostAsync(
            on.Client,
            "/identity/emailCode/verify",
            new { email = known, code = Codes(on.Mail, known).Single() });
        Assert.Equal(HttpStatusCode.OK, existing.StatusCode);
        Assert.Equal(knownId, await UserIdAsync(on.App, known));
        Assert.True(await HasPasswordAsync(on.App, known));
        Assert.Equal(1, await CountUsersAsync(on.App, known));
    }

    [Fact]
    public async Task AllowSignUp_ParallelVerifiesCreateOneUser()
    {
        await using var host = await EmailCodeHost.StartAsync(options => options.AllowSignUp = true);
        var email = UniqueEmail("signup-race");
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();
        using var clientA = host.App.GetTestClient();
        using var clientB = host.App.GetTestClient();
        var results = await Task.WhenAll(
            PostAsync(clientA, "/identity/emailCode/verify", new { email, code }),
            PostAsync(clientB, "/identity/emailCode/verify", new { email, code }));
        await AssertNoServerErrorAsync(results);
        Assert.Equal(1, results.Count(response => response.StatusCode == HttpStatusCode.OK));
        Assert.Equal(1, results.Count(response => response.StatusCode == HttpStatusCode.Unauthorized));
        Assert.Equal(1, await CountUsersAsync(host.App, email));
        Assert.True(await IsConfirmedAsync(host.App, email));
        Assert.False(await HasPasswordAsync(host.App, email));
    }

    [Fact]
    public async Task AllowSignUp_ParallelTokensCreateOneUser_AndALaterUserKeepsItsPassword()
    {
        await using (var host = await EmailCodeHost.StartAsync(options =>
        {
            options.AllowSignUp = true;
            EnableLink(options);
        }))
        {
            var email = UniqueEmail("signup-dup");
            var createdAt = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var emailHash = EmailCodeHasher.HashEmail(new UpperInvariantLookupNormalizer().NormalizeEmail(email.Trim())!);
            var tokenA = EmailCodeGenerator.CreateLinkToken();
            var tokenB = EmailCodeGenerator.CreateLinkToken();
            using (var scope = host.App.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                db.Add(NewSignupRow(email, emailHash, tokenA, createdAt));
                db.Add(NewSignupRow(email, emailHash, tokenB, createdAt.AddSeconds(1)));
                await db.SaveChangesAsync();
            }

            using var clientA = host.App.GetTestClient();
            using var clientB = host.App.GetTestClient();
            var results = await Task.WhenAll(
                PostAsync(clientA, "/identity/emailCode/verify", new { token = tokenA }),
                PostAsync(clientB, "/identity/emailCode/verify", new { token = tokenB }));
            await AssertNoServerErrorAsync(results);
            Assert.Contains(results, response => response.StatusCode == HttpStatusCode.OK);
            Assert.All(results, response => Assert.True(
                response.StatusCode is HttpStatusCode.OK or HttpStatusCode.Unauthorized,
                response.StatusCode.ToString()));
            Assert.Equal(1, await CountUsersAsync(host.App, email));
            Assert.True(await IsConfirmedAsync(host.App, email));
            Assert.False(await HasPasswordAsync(host.App, email));
        }

        await using var later = await EmailCodeHost.StartAsync(options => options.AllowSignUp = true);
        var existingEmail = UniqueEmail("signup-later");
        await PostAsync(later.Client, "/identity/emailCode/send", new { email = existingEmail });
        var code = Codes(later.Mail, existingEmail).Single();
        await SeedAsync(later.App, existingEmail);
        var userId = await UserIdAsync(later.App, existingEmail);
        var signedIn = await PostAsync(later.Client, "/identity/emailCode/verify", new { email = existingEmail, code });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        Assert.Equal(userId, await UserIdAsync(later.App, existingEmail));
        Assert.True(await HasPasswordAsync(later.App, existingEmail));
        Assert.Equal(1, await CountUsersAsync(later.App, existingEmail));
    }

    [Fact]
    public async Task AllowSignUp_DbUpdateException_UsesTheExistingUser_OrReturns401()
    {
        var race = new SignupCreateGate { Mode = SignupCreateMode.UniqueConflict };
        await using (var host = await EmailCodeHost.StartAsync(
            options => options.AllowSignUp = true,
            configureServices: services =>
            {
                services.AddSingleton(race);
                services.RemoveAll<IUserValidator<TestAppUser>>();
                services.Replace(ServiceDescriptor.Scoped<UserManager<TestAppUser>, ConflictSignupUserManager>());
            }))
        {
            var email = UniqueEmail("signup-conflict");
            await PostAsync(host.Client, "/identity/emailCode/send", new { email });
            race.Email = email;
            var response = await PostAsync(
                host.Client,
                "/identity/emailCode/verify",
                new { email, code = Codes(host.Mail, email).Single() });
            var body = await response.Content.ReadAsStringAsync();
            Assert.True(response.StatusCode == HttpStatusCode.OK, body);
            Assert.True(race.Claimed);
            Assert.Equal(1, await CountUsersAsync(host.App, email));
            Assert.Equal(race.CreatedUserId, await UserIdAsync(host.App, email));
            Assert.True(await IsConfirmedAsync(host.App, email));
            Assert.True(await HasPasswordAsync(host.App, email));
        }

        var missing = new SignupCreateGate { Mode = SignupCreateMode.RequiredColumn };
        await using var failed = await EmailCodeHost.StartAsync(
            options => options.AllowSignUp = true,
            configureServices: services =>
            {
                services.AddSingleton(missing);
                services.Replace(ServiceDescriptor.Scoped<UserManager<TestAppUser>, ConflictSignupUserManager>());
            });
        var unknown = UniqueEmail("signup-required");
        await PostAsync(failed.Client, "/identity/emailCode/send", new { email = unknown });
        missing.Email = unknown;
        var rejected = await PostAsync(
            failed.Client,
            "/identity/emailCode/verify",
            new { email = unknown, code = Codes(failed.Mail, unknown).Single() });
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        Assert.Equal("Unauthorized", await ProblemTitleAsync(rejected));
        Assert.True(missing.Claimed);
        Assert.Equal(0, await CountUsersAsync(failed.App, unknown));
        var row = (await RowsAsync(failed.App, unknown)).Single();
        Assert.NotNull(row.ConsumedAt);
        Assert.Equal(1, row.Attempts);
    }

    [Fact]
    public async Task AllowSignUp_DuplicateRequiresTwoFactor_ReleasesTheReservedAttempt()
    {
        var race = new SignupCreateGate { Mode = SignupCreateMode.UniqueConflict, TwoFactor = true };
        await using var host = await EmailCodeHost.StartAsync(
            options => options.AllowSignUp = true,
            configureServices: services =>
            {
                services.AddSingleton(race);
                services.RemoveAll<IUserValidator<TestAppUser>>();
                services.Replace(ServiceDescriptor.Scoped<UserManager<TestAppUser>, ConflictSignupUserManager>());
            });
        var email = UniqueEmail("signup-2fa-race");
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();
        race.Email = email;

        var missing = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
        var missingBody = await missing.Content.ReadAsStringAsync();
        Assert.True(missing.StatusCode == HttpStatusCode.Unauthorized, missingBody);
        using (var doc = JsonDocument.Parse(missingBody))
        {
            Assert.Equal("RequiresTwoFactor", doc.RootElement.GetProperty("title").GetString());
        }

        Assert.True(race.Claimed);
        var reserved = (await RowsAsync(host.App, email)).Single();
        Assert.Null(reserved.ConsumedAt);
        Assert.Equal(0, reserved.Attempts);
        Assert.Equal(1, await CountUsersAsync(host.App, email));
        Assert.True(await HasPasswordAsync(host.App, email));
        Assert.Equal(race.CreatedUserId, await UserIdAsync(host.App, email));

        var key = await AuthenticatorKeyAsync(host.App, email);
        var accepted = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code, twoFactorCode = TotpHelper.GenerateCode(key) });
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.NotNull((await RowsAsync(host.App, email)).Single().ConsumedAt);
        Assert.True(await HasPasswordAsync(host.App, email));
    }

    [Fact]
    public async Task AllowSignUp_DuplicateWrongTotp_UnconsumesAndKeepsTheAttempt()
    {
        var race = new SignupCreateGate { Mode = SignupCreateMode.UniqueConflict, TwoFactor = true };
        await using var host = await EmailCodeHost.StartAsync(
            options => options.AllowSignUp = true,
            configureServices: services =>
            {
                services.AddSingleton(race);
                services.RemoveAll<IUserValidator<TestAppUser>>();
                services.Replace(ServiceDescriptor.Scoped<UserManager<TestAppUser>, ConflictSignupUserManager>());
            });
        var email = UniqueEmail("signup-2fa-wrong");
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();
        race.Email = email;

        var wrong = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code, twoFactorCode = "000000" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal("Unauthorized", await ProblemTitleAsync(wrong));
        var reserved = (await RowsAsync(host.App, email)).Single();
        Assert.Null(reserved.ConsumedAt);
        Assert.Equal(1, reserved.Attempts);

        var key = await AuthenticatorKeyAsync(host.App, email);
        Assert.NotEqual("000000", TotpHelper.GenerateCode(key));
        var accepted = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code, twoFactorCode = TotpHelper.GenerateCode(key) });
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.NotNull((await RowsAsync(host.App, email)).Single().ConsumedAt);
    }

    [Fact]
    public async Task AllowSignUp_ConfirmsEmailWithoutATokenProvider()
    {
        await using var host = await EmailCodeHost.StartAsync(
            options => options.AllowSignUp = true,
            configureServices: services => services.PostConfigure<IdentityOptions>(options =>
            {
                options.Tokens.ProviderMap.Clear();
                options.Tokens.EmailConfirmationTokenProvider = "Missing";
            }));
        var email = UniqueEmail("signup-notoken");
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var created = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code = Codes(host.Mail, email).Single() });
        var body = await created.Content.ReadAsStringAsync();
        Assert.True(created.StatusCode == HttpStatusCode.OK, body);
        Assert.Equal(1, await CountUsersAsync(host.App, email));
        Assert.True(await IsConfirmedAsync(host.App, email));
        Assert.False(await HasPasswordAsync(host.App, email));
        Assert.DoesNotContain(host.Mail.Snapshot(), item => item.Kind == "confirm" && item.Email == email);

        using var scope = host.App.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        var tokenError = await Assert.ThrowsAnyAsync<Exception>(() => userManager.GenerateEmailConfirmationTokenAsync(user!));
        Assert.Contains("Token", tokenError.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MagicLink_FragmentUrl_PostVerifiesOnce_AndGetDoesNotSignIn()
    {
        await using var host = await EmailCodeHost.StartAsync(options => EnableLink(options), captureLogs: true);
        var email = UniqueEmail("link");
        await SeedAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var mail = MailFor(host.Mail, email);
        var token = TokenFromLink(mail.LinkUrl);
        Assert.Equal("https://app.example.com/auth/email-link#token=" + token, mail.LinkUrl);
        Assert.Equal(EmailCodeHasher.HashLinkToken(token), (await RowsAsync(host.App, email)).Single().LinkTokenHash);
        foreach (var message in host.Logs.Messages)
        {
            Assert.DoesNotContain(token, message, StringComparison.Ordinal);
            Assert.DoesNotContain(mail.LinkUrl!, message, StringComparison.Ordinal);
            Assert.DoesNotContain(email, message, StringComparison.Ordinal);
            Assert.DoesNotContain(mail.Body, message, StringComparison.Ordinal);
        }

        var get = await host.Client.GetAsync("/identity/emailCode/verify?token=" + Uri.EscapeDataString(token));
        Assert.Equal(HttpStatusCode.MethodNotAllowed, get.StatusCode);
        Assert.DoesNotContain(".AspNetCore.Identity.Application", SetCookie(get), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Client.GetAsync("/identity/manage/info")).StatusCode);
        Assert.Null((await RowsAsync(host.App, email)).Single().ConsumedAt);

        var ok = await PostAsync(host.Client, "/identity/emailCode/verify", new { token });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        using (var doc = JsonDocument.Parse(await ok.Content.ReadAsStringAsync()))
        {
            Assert.False(string.IsNullOrWhiteSpace(TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken")));
        }

        var replay = await PostAsync(host.Client, "/identity/emailCode/verify", new { token });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        var codeAfter = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = mail.Body });
        Assert.Equal(HttpStatusCode.Unauthorized, codeAfter.StatusCode);
        Assert.Equal("Unauthorized", await ProblemTitleAsync(codeAfter));
    }

    [Fact]
    public async Task MagicLink_CodeConsumesTheToken_AndTheOverrideIsHonoured()
    {
        await using (var host = await EmailCodeHost.StartAsync(options => EnableLink(options)))
        {
            var email = UniqueEmail("link-code");
            await SeedAsync(host.App, email);
            await PostAsync(host.Client, "/identity/emailCode/send", new { email });
            var mail = MailFor(host.Mail, email);
            var token = TokenFromLink(mail.LinkUrl);
            var signedIn = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = mail.Body });
            Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
            var tokenAfter = await PostAsync(host.Client, "/identity/emailCode/verify", new { token });
            Assert.Equal(HttpStatusCode.Unauthorized, tokenAfter.StatusCode);
        }

        await using var custom = await EmailCodeHost.StartAsync(options =>
        {
            EnableLink(options);
            options.MagicLink.BuildLinkUrl = context => context.LinkUri + "#custom=" + context.Token;
        });
        var customEmail = UniqueEmail("link-custom");
        await SeedAsync(custom.App, customEmail);
        await PostAsync(custom.Client, "/identity/emailCode/send", new { email = customEmail });
        var customMail = MailFor(custom.Mail, customEmail);
        const string customPrefix = "https://app.example.com/auth/email-link#custom=";
        Assert.StartsWith(customPrefix, customMail.LinkUrl, StringComparison.Ordinal);
        var customToken = customMail.LinkUrl![customPrefix.Length..];
        Assert.Equal(EmailCodeHasher.HashLinkToken(customToken), (await RowsAsync(custom.App, customEmail)).Single().LinkTokenHash);
    }

    [Fact]
    public async Task MagicLink_Disabled_RejectsAToken()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("link-off");
        await SeedAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();
        Assert.Null(MailFor(host.Mail, email).LinkUrl);

        var tokenOnly = await PostAsync(host.Client, "/identity/emailCode/verify", new { token = "abc" });
        Assert.Equal(HttpStatusCode.BadRequest, tokenOnly.StatusCode);
        var both = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code, token = "abc" });
        Assert.Equal(HttpStatusCode.BadRequest, both.StatusCode);
        using (var doc = JsonDocument.Parse(await both.Content.ReadAsStringAsync()))
        {
            Assert.True(doc.RootElement.GetProperty("errors").TryGetProperty("InvalidEmailCodeRequest", out _));
        }

        Assert.Null((await RowsAsync(host.App, email)).Single().ConsumedAt);
        var signedIn = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
    }

    [Fact]
    public async Task MagicLink_TokenRequiresTwoFactor_AndSharesAttemptsAndExpiryWithTheCode()
    {
        await using (var host = await EmailCodeHost.StartAsync(options => EnableLink(options)))
        {
            var email = UniqueEmail("link-totp");
            await SeedAsync(host.App, email, twoFactor: true);
            var key = await AuthenticatorKeyAsync(host.App, email);
            await PostAsync(host.Client, "/identity/emailCode/send", new { email });
            var token = TokenFromLink(MailFor(host.Mail, email).LinkUrl);
            var missing = await PostAsync(host.Client, "/identity/emailCode/verify", new { token });
            Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
            Assert.Equal("RequiresTwoFactor", await ProblemTitleAsync(missing));
            Assert.Equal("Two-factor authentication is required.", await ProblemDetailAsync(missing));
            Assert.Null((await RowsAsync(host.App, email)).Single().ConsumedAt);

            var accepted = await PostAsync(
                host.Client,
                "/identity/emailCode/verify",
                new { token, twoFactorCode = TotpHelper.GenerateCode(key) });
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            Assert.NotNull((await RowsAsync(host.App, email)).Single().ConsumedAt);
        }

        await using (var attempts = await EmailCodeHost.StartAsync(options =>
        {
            EnableLink(options);
            options.MaxAttempts = 2;
        }))
        {
            var email = UniqueEmail("link-attempts");
            await SeedAsync(attempts.App, email);
            await PostAsync(attempts.Client, "/identity/emailCode/send", new { email });
            var mail = MailFor(attempts.Mail, email);
            var token = TokenFromLink(mail.LinkUrl);
            await PostAsync(attempts.Client, "/identity/emailCode/verify", new { email, code = WrongCode(mail.Body) });
            await PostAsync(attempts.Client, "/identity/emailCode/verify", new { email, code = WrongCode(mail.Body) });
            var blocked = await PostAsync(attempts.Client, "/identity/emailCode/verify", new { token });
            Assert.Equal(HttpStatusCode.Unauthorized, blocked.StatusCode);
            var row = (await RowsAsync(attempts.App, email)).Single();
            Assert.Equal(2, row.Attempts);
            Assert.Null(row.ConsumedAt);
        }

        await using var expired = await EmailCodeHost.StartAsync(options => EnableLink(options));
        var expiredEmail = UniqueEmail("link-expired");
        await SeedAsync(expired.App, expiredEmail);
        await PostAsync(expired.Client, "/identity/emailCode/send", new { email = expiredEmail });
        var expiredToken = TokenFromLink(MailFor(expired.Mail, expiredEmail).LinkUrl);
        expired.Clock.Advance(TimeSpan.FromMinutes(11));
        var expiredVerify = await PostAsync(expired.Client, "/identity/emailCode/verify", new { token = expiredToken });
        Assert.Equal(HttpStatusCode.Unauthorized, expiredVerify.StatusCode);
        Assert.Null((await RowsAsync(expired.App, expiredEmail)).Single().ConsumedAt);
    }

    [Fact]
    public async Task Verify_GetRouteIsAbsent_AndTokenShapeIsRejected()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var get = await host.Client.GetAsync("/identity/emailCode/verify");
        Assert.Equal(HttpStatusCode.MethodNotAllowed, get.StatusCode);
        Assert.DoesNotContain(".AspNetCore.Identity.Application", SetCookie(get), StringComparison.Ordinal);

        var tokenOnly = await PostAsync(host.Client, "/identity/emailCode/verify", new { token = "abc" });
        Assert.Equal(HttpStatusCode.BadRequest, tokenOnly.StatusCode);
        using (var doc = JsonDocument.Parse(await tokenOnly.Content.ReadAsStringAsync()))
        {
            Assert.True(doc.RootElement.GetProperty("errors").TryGetProperty("InvalidEmailCodeRequest", out _));
        }

        var both = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email = "a@x.com", code = "000000", token = "abc" });
        Assert.Equal(HttpStatusCode.BadRequest, both.StatusCode);

        var letters = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email = "a@x.com", code = "12ab56" });
        Assert.Equal(HttpStatusCode.BadRequest, letters.StatusCode);
    }

    [Fact]
    public async Task Verify_DoesNotIssueReAuthProof()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("reauth");
        await SeedAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var jar = new CookieJar();
        var signedIn = await PostAsync(
            host.Client,
            "/identity/emailCode/verify?useSessionCookies=true",
            new { email, code = Codes(host.Mail, email).Single() },
            jar);
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);

        var blocked = await GetAsync(host.Client, "/test/reauth", jar);
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

        var csrf = await GetAsync(host.Client, "/identity/csrfToken", jar);
        Assert.Equal(HttpStatusCode.OK, csrf.StatusCode);
        using var csrfDoc = JsonDocument.Parse(await csrf.Content.ReadAsStringAsync());
        var token = csrfDoc.RootElement.TryGetProperty("csrfToken", out var camel)
            ? camel.GetString()
            : csrfDoc.RootElement.GetProperty("CsrfToken").GetString();

        using var confirm = new HttpRequestMessage(HttpMethod.Post, "/identity/confirmIdentity")
        {
            Content = JsonContent.Create(new { password = TestHelpers.DefaultPassword })
        };
        confirm.Headers.TryAddWithoutValidation("RequestVerificationToken", token);
        jar.Apply(confirm, host.Client.BaseAddress!);
        var confirmed = await host.Client.SendAsync(confirm);
        jar.Capture(confirmed, host.Client.BaseAddress!);
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);

        var allowed = await GetAsync(host.Client, "/test/reauth", jar);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
    }

    [Fact]
    public async Task Send_SenderThrows_Returns200AndLeavesTheCodeUnconsumed()
    {
        var sender = new SelectiveEmailCodeSender();
        await using var host = await EmailCodeHost.StartAsync(sender: sender);
        var email = UniqueEmail("throw");
        await SeedAsync(host.App, email);
        var response = await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var code = Codes(sender.Inner, email).Single();
        var row = (await RowsAsync(host.App, email)).Single();
        Assert.Null(row.ConsumedAt);
        Assert.Equal(0, row.Attempts);

        var verify = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
    }

    [Fact]
    public async Task Logs_OmitCodeAndRawEmail()
    {
        await using var host = await EmailCodeHost.StartAsync(captureLogs: true);
        var email = UniqueEmail("audit");
        await SeedAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();
        await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = WrongCode(code) });

        var messages = host.Logs.Messages;
        Assert.Contains(messages, message => message.Contains("CodeIssued", StringComparison.Ordinal));
        Assert.Contains(messages, message => message.Contains("VerifyFailed", StringComparison.Ordinal));
        foreach (var message in messages)
        {
            Assert.DoesNotContain(code, message, StringComparison.Ordinal);
            Assert.DoesNotContain(email, message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Production_RejectsMissingOrDevelopmentSender_AndAcceptsARealOne()
    {
        using (var missing = BuildProductionHost(sender: null, developmentSender: false, requireSender: true))
        {
            var ex = Assert.ThrowsAny<Exception>(() => _ = missing.Services.GetRequiredService<IOptions<EmailCodeOptions>>().Value);
            Assert.Contains("IEmailCodeSender", ex.ToString(), StringComparison.Ordinal);
        }

        using (var development = BuildProductionHost(sender: null, developmentSender: true, requireSender: true))
        {
            var ex = Assert.ThrowsAny<Exception>(() => _ = development.Services.GetRequiredService<IOptions<EmailCodeOptions>>().Value);
            Assert.Contains("IEmailCodeSender", ex.ToString(), StringComparison.Ordinal);
        }

        await using (var real = BuildProductionHost(sender: new StubEmailCodeSender(), developmentSender: false, requireSender: true))
        {
            _ = real.Services.GetRequiredService<IOptions<EmailCodeOptions>>().Value;
            await real.StartAsync();
        }

        await using (var optedOut = BuildProductionHost(sender: null, developmentSender: false, requireSender: false))
        {
            _ = optedOut.Services.GetRequiredService<IOptions<EmailCodeOptions>>().Value;
            await optedOut.StartAsync();
        }

        using (var staging = BuildProductionHost(sender: null, developmentSender: false, requireSender: true, environmentName: Environments.Staging))
        {
            var ex = Assert.ThrowsAny<Exception>(() => _ = staging.Services.GetRequiredService<IOptions<EmailCodeOptions>>().Value);
            Assert.Contains("IEmailCodeSender", ex.ToString(), StringComparison.Ordinal);
        }

        using (var development = BuildProductionHost(sender: null, developmentSender: false, requireSender: true, environmentName: Environments.Development))
        {
            _ = development.Services.GetRequiredService<IOptions<EmailCodeOptions>>().Value;
        }
    }

    [Fact]
    public async Task Send_TaskCanceledException_ReturnsTheSame200AsAnUnknownAddress()
    {
        await using var host = await EmailCodeHost.StartAsync(sender: new TimingOutEmailCodeSender());
        var known = UniqueEmail("timeout");
        var unknown = UniqueEmail("timeout-unknown");
        await SeedAsync(host.App, known);

        var knownResponse = await PostAsync(host.Client, "/identity/emailCode/send", new { email = known });
        var unknownResponse = await PostAsync(host.Client, "/identity/emailCode/send", new { email = unknown });

        Assert.Equal(HttpStatusCode.OK, knownResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, unknownResponse.StatusCode);
        Assert.Equal(await unknownResponse.Content.ReadAsStringAsync(), await knownResponse.Content.ReadAsStringAsync());
        Assert.Equal(StableHeaders(unknownResponse), StableHeaders(knownResponse));
        var row = (await RowsAsync(host.App, known)).Single();
        Assert.Null(row.ConsumedAt);
        Assert.Equal(0, row.Attempts);
    }

    [Fact]
    public async Task Verify_ParallelAttemptCap_ComparesAtMostMaxAttempts()
    {
        const int maxAttempts = 5;
        var counter = new CompareCounter();
        var loaded = new Barrier(21);
        await using var host = await EmailCodeHost.StartAsync(
            options => options.MaxAttempts = maxAttempts,
            configureServices: services => services.AddScoped<IEmailCodeStore>(sp => new GatedEmailCodeStore(
                CreateStore(sp),
                counter,
                loaded)),
            useRateLimiter: false);
        var email = UniqueEmail("cap-race");
        await SeedAsync(host.App, email);
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(host.Client, "/identity/emailCode/send", new { email })).StatusCode);
        var code = Codes(host.Mail, email).Single();
        var wrong = WrongCode(code);

        var attempts = new List<Task<HttpResponseMessage>>();
        for (var i = 0; i < 20; i++)
        {
            attempts.Add(PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = wrong }));
        }

        attempts.Add(PostAsync(host.Client, "/identity/emailCode/verify", new { email, code }));
        var results = await Task.WhenAll(attempts);
        var unexpected = results.Where(response => response.StatusCode is not HttpStatusCode.OK and not HttpStatusCode.Unauthorized).ToArray();
        Assert.True(unexpected.Length == 0, string.Join(", ", unexpected.Select(response => (int)response.StatusCode)));
        Assert.InRange(counter.Compares, 1, maxAttempts);
        Assert.True(results.Count(response => response.StatusCode == HttpStatusCode.OK) <= 1);

        var followUp = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
        Assert.Equal(HttpStatusCode.Unauthorized, followUp.StatusCode);
        var row = (await RowsAsync(host.App, email)).Single();
        if (row.ConsumedAt is null)
        {
            Assert.Equal(maxAttempts, row.Attempts);
            Assert.DoesNotContain(results, response => response.StatusCode == HttpStatusCode.OK);
        }
    }

    [Fact]
    public async Task Verify_CredentialResetFailure_DoesNotConfirmOrSignIn()
    {
        await using var host = await EmailCodeHost.StartAsync(configureServices: services =>
            services.Replace(ServiceDescriptor.Scoped<UserManager<TestAppUser>, FailingPasswordUserManager>()));
        var email = UniqueEmail("reset-fail");
        await SeedAsync(host.App, email, confirmed: false);
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(host.Client, "/identity/emailCode/send", new { email })).StatusCode);
        var response = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code = Codes(host.Mail, email).Single() });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Unauthorized", await ProblemTitleAsync(response));
        Assert.False(await IsConfirmedAsync(host.App, email));
        Assert.True(await HasPasswordAsync(host.App, email));
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Verify_WrongRecoveryCode_DoesNotSpendEitherSecret()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("recovery-wrong");
        await SeedAsync(host.App, email, twoFactor: true);
        var recoveryCode = await RecoveryCodeAsync(host.App, email);
        var before = await RecoveryCodeCountAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();
        var response = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code, twoFactorRecoveryCode = "not-a-code" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(before, await RecoveryCodeCountAsync(host.App, email));
        Assert.True(await RecoveryCodeStillValidAsync(host.App, email, recoveryCode));
        var row = (await RowsAsync(host.App, email)).Single();
        Assert.Null(row.ConsumedAt);
        Assert.Equal(1, row.Attempts);
    }

    [Fact]
    public async Task Verify_RecoveryCode_IsSpentOnlyAfterTheEmailCodeIsConsumed()
    {
        var loaded = new Barrier(2);
        await using var host = await EmailCodeHost.StartAsync(configureServices: services =>
            services.AddScoped<IEmailCodeStore>(sp => new GatedEmailCodeStore(CreateStore(sp), new CompareCounter(), loaded)));
        var email = UniqueEmail("recovery-race");
        await SeedAsync(host.App, email, twoFactor: true);
        var recoveryCode = await RecoveryCodeAsync(host.App, email);
        var before = await RecoveryCodeCountAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var code = Codes(host.Mail, email).Single();

        using var clientA = host.App.GetTestClient();
        using var clientB = host.App.GetTestClient();
        var results = await Task.WhenAll(
            PostAsync(clientA, "/identity/emailCode/verify", new { email, code, twoFactorRecoveryCode = recoveryCode }),
            PostAsync(clientB, "/identity/emailCode/verify", new { email, code, twoFactorRecoveryCode = recoveryCode }));
        Assert.Equal(1, results.Count(response => response.StatusCode == HttpStatusCode.OK));
        Assert.Equal(1, results.Count(response => response.StatusCode == HttpStatusCode.Unauthorized));
        Assert.Equal(before - 1, await RecoveryCodeCountAsync(host.App, email));
        Assert.False(await RecoveryCodeStillValidAsync(host.App, email, recoveryCode));
        Assert.NotNull((await RowsAsync(host.App, email)).Single().ConsumedAt);
    }

    [Fact]
    public async Task Verify_RecoveryRedeemFailure_UnconsumesTheEmailCode()
    {
        await using var host = await EmailCodeHost.StartAsync(configureServices: services =>
            services.Replace(ServiceDescriptor.Scoped<UserManager<TestAppUser>, FailingRecoveryUserManager>()));
        var email = UniqueEmail("recovery-unconsume");
        await SeedAsync(host.App, email, twoFactor: true);
        var recoveryCode = await RecoveryCodeAsync(host.App, email);
        var before = await RecoveryCodeCountAsync(host.App, email);
        await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        var response = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code = Codes(host.Mail, email).Single(), twoFactorRecoveryCode = recoveryCode });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(before, await RecoveryCodeCountAsync(host.App, email));
        var row = (await RowsAsync(host.App, email)).Single();
        Assert.Null(row.ConsumedAt);
        Assert.Equal(1, row.Attempts);
    }

    [Fact]
    public async Task Send_SerializationFailure_ReturnsTheSameBodyAsANormalSend()
    {
        string normalBody;
        await using (var host = await EmailCodeHost.StartAsync())
        {
            var email = UniqueEmail("conflict-baseline");
            await SeedAsync(host.App, email);
            var response = await PostAsync(host.Client, "/identity/emailCode/send", new { email });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            normalBody = await response.Content.ReadAsStringAsync();
        }

        var throwing = new SerializationFailureStore();
        await using var failed = await EmailCodeHost.StartAsync(configureServices: services =>
            services.AddScoped<IEmailCodeStore>(_ => throwing));
        var conflictEmail = UniqueEmail("conflict");
        await SeedAsync(failed.App, conflictEmail);
        var conflict = await PostAsync(failed.Client, "/identity/emailCode/send", new { email = conflictEmail });
        Assert.Equal(HttpStatusCode.OK, conflict.StatusCode);
        Assert.Equal(normalBody, await conflict.Content.ReadAsStringAsync());
        Assert.Equal(2, throwing.IssueCalls);
        Assert.Empty(Codes(failed.Mail, conflictEmail));
    }

    [Fact]
    public async Task Send_WithRetryingExecutionStrategy_IssuesTheCode()
    {
        await using var host = await EmailCodeHost.StartAsync(configureSqlite: sqlite =>
            sqlite.ExecutionStrategy(dependencies => new RetryingExecutionStrategy(dependencies)));
        using (var scope = host.App.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            Assert.True(db.Database.CreateExecutionStrategy().RetriesOnFailure);
        }

        var email = UniqueEmail("retry-strategy");
        await SeedAsync(host.App, email);
        var response = await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(Codes(host.Mail, email));
        Assert.Single(await RowsAsync(host.App, email));
    }

    [Fact]
    public async Task SendAndVerify_UsesTheRegisteredLookupNormalizer()
    {
        var normalizer = new PrefixLookupNormalizer();
        await using var host = await EmailCodeHost.StartAsync(configureServices: services =>
        {
            services.RemoveAll<ILookupNormalizer>();
            services.AddSingleton<ILookupNormalizer>(normalizer);
        });
        var email = UniqueEmail("normalizer");
        await SeedAsync(host.App, email);

        var response = await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var normalized = normalizer.NormalizeEmail(email);
        Assert.StartsWith("ee:", normalized, StringComparison.Ordinal);
        var row = Assert.Single(await RowsAsync(host.App, email));
        Assert.Equal(EmailCodeHasher.HashEmail(normalized!), row.EmailHash);

        var verify = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code = Codes(host.Mail, email).Single() });
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
    }

    [Fact]
    public async Task Send_ParallelWithinCooldown_IssuesOneRowAndOneMail()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("cooldown-race");
        await SeedAsync(host.App, email);
        var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ =>
            PostAsync(host.Client, "/identity/emailCode/send", new { email })));
        Assert.All(results, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
        Assert.Single(Codes(host.Mail, email));
        Assert.Single(await RowsAsync(host.App, email));
    }

    [Fact]
    public void Map_WithoutUseEmailCodes_Throws()
    {
        using var missing = BuildMapHost<UnmappedEmailCodeDbContext>();
        var ex = Assert.Throws<NotSupportedException>(() => missing.MapEmailCodeEndpoints<TestAppUser>());
        Assert.Contains("UseEmailCodes", ex.Message, StringComparison.Ordinal);

        using var mapped = BuildMapHost<MappedEmailCodeDbContext>();
        mapped.MapEmailCodeEndpoints<TestAppUser>();
    }

    private static WebApplication BuildProductionHost(
        IEmailCodeSender<TestAppUser>? sender,
        bool developmentSender,
        bool requireSender,
        string? environmentName = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = environmentName ?? Environments.Production
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(options =>
            options.UseInMemoryDatabase("EmailCodeProd_" + Guid.NewGuid().ToString("N")));
        builder.Services.AddSingleton<IEmailSender<TestAppUser>, TestEmailSender>();
        if (sender is not null)
        {
            builder.Services.AddSingleton(sender);
        }

        if (developmentSender)
        {
            builder.Services.AddSingleton<IEmailCodeSender<TestAppUser>, DevelopmentEmailCodeSender<TestAppUser>>();
        }

        builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(options =>
        {
            options.Passkeys.ServerDomain = "example.com";
            options.RequireEmailSenderInProduction = false;
            options.EmailCode.Enabled = true;
            options.EmailCode.Configure = emailCode => emailCode.RequireSenderOutsideDevelopment = requireSender;
        });
        return builder.Build();
    }

    private static async Task<WebApplication> StartFacadeAsync(bool enabled, string identityPath = "/identity")
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(options =>
            options.UseInMemoryDatabase("EmailCodeFacade_" + Guid.NewGuid().ToString("N")));
        builder.Services.AddSingleton<IEmailSender<TestAppUser>, TestEmailSender>();
        builder.Services.AddSingleton<IEmailCodeSender<TestAppUser>, CapturingEmailSender>();
        builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(options =>
        {
            options.IdentityPath = identityPath;
            options.Passkeys.ServerDomain = "localhost";
            options.RequireConfirmedAccount = false;
            options.EmailCode.Enabled = enabled;
            options.ConfigureIdentity = identity =>
            {
                identity.SignIn.RequireConfirmedAccount = false;
                identity.Password.RequireDigit = false;
                identity.Password.RequireLowercase = false;
                identity.Password.RequireUppercase = false;
                identity.Password.RequireNonAlphanumeric = false;
                identity.Password.RequiredLength = 6;
            };
        });

        var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<TestDbContext>().Database.EnsureCreatedAsync();
        }

        app.UseAuthEndpoints();
        app.MapAuthEndpoints<TestAppUser>();
        await app.StartAsync();
        return app;
    }

    private static void EnableLink(EmailCodeOptions options)
    {
        options.MagicLink.Enabled = true;
        options.MagicLink.LinkUri = "https://app.example.com/auth/email-link";
    }

    private static CapturedMail MailFor(CapturingEmailSender mail, string email)
    {
        return mail.Snapshot().Single(item => item.Kind == "email-code" && item.Email == email);
    }

    private static string TokenFromLink(string? link)
    {
        const string marker = "#token=";
        Assert.NotNull(link);
        var index = link.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(index >= 0, link);
        var token = link[(index + marker.Length)..];
        Assert.False(string.IsNullOrEmpty(token));
        Assert.DoesNotContain(token, link[..index], StringComparison.Ordinal);
        return token;
    }

    private static EmailCodeEntity NewSignupRow(string email, string emailHash, string token, DateTime createdAt)
    {
        var id = Guid.NewGuid().ToString();
        return new EmailCodeEntity
        {
            Id = id,
            EmailHash = emailHash,
            CodeHash = EmailCodeHasher.HashCode(id, "000000"),
            LinkTokenHash = EmailCodeHasher.HashLinkToken(token),
            SignupEmail = email,
            CreatedAt = createdAt,
            ExpiresAt = createdAt.AddMinutes(10)
        };
    }

    private static async Task<int> CountUsersAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var normalized = userManager.NormalizeEmail(email);
        return await userManager.Users.CountAsync(user => user.NormalizedEmail == normalized);
    }

    private static async Task<string> UserIdAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return await userManager.GetUserIdAsync(user!);
    }

    private static List<string> Codes(CapturingEmailSender mail, string email)
    {
        return mail.Snapshot()
            .Where(item => item.Kind == "email-code" && item.Email == email)
            .Select(item => item.Body)
            .ToList();
    }

    private static async Task AssertNoServerErrorAsync(IEnumerable<HttpResponseMessage> responses)
    {
        foreach (var response in responses)
        {
            if ((int)response.StatusCode < 500)
            {
                continue;
            }

            var body = await response.Content.ReadAsStringAsync();
            Assert.Fail($"{(int)response.StatusCode} {body}");
        }
    }

    private static string UniqueEmail(string label) => $"{label}-{Guid.NewGuid():N}@test.local";

    private static string WrongCode(string code)
    {
        var wrong = new string('0', code.Length);
        return wrong == code ? new string('1', code.Length) : wrong;
    }

    private static string StableHeaders(HttpResponseMessage response)
    {
        var headers = response.Headers
            .Concat(response.Content.Headers)
            .Where(header => !IsVolatileHeader(header.Key))
            .OrderBy(header => header.Key, StringComparer.OrdinalIgnoreCase)
            .Select(header => header.Key + "=" + string.Join(",", header.Value));
        return string.Join("\n", headers);
    }

    private static bool IsVolatileHeader(string name)
    {
        return name.Equals("Date", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Retry-After", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("X-Rate-Limit-", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("RateLimit-", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("X-RateLimit-", StringComparison.OrdinalIgnoreCase);
    }

    private static EmailCodeStore<TestDbContext> CreateStore(IServiceProvider services)
    {
        return new EmailCodeStore<TestDbContext>(
            services.GetRequiredService<TestDbContext>(),
            services.GetRequiredService<TimeProvider>(),
            services.GetRequiredService<IOptions<EmailCodeOptions>>().Value,
            services.GetRequiredService<ILookupNormalizer>());
    }

    private static WebApplication BuildMapHost<TContext>()
        where TContext : DbContext
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TContext>(options =>
            options.UseInMemoryDatabase("EmailCodeMap_" + Guid.NewGuid().ToString("N")));
        builder.Services.AddSingleton<IEmailCodeSignInCompleter<TestAppUser>, UnusedEmailCodeSignInCompleter>();
        builder.Services.AddEmailCodeEndpoints<TestAppUser, TContext>();
        return builder.Build();
    }

    private static string SetCookie(HttpResponseMessage response)
    {
        return response.Headers.TryGetValues("Set-Cookie", out var values)
            ? string.Join("\n", values)
            : "";
    }

    private static async Task<string?> ProblemTitleAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("title").GetString();
    }

    private static async Task<string?> ProblemDetailAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("detail").GetString();
    }

    private static async Task<HttpResponseMessage> PostAsync(HttpClient client, string url, object body, CookieJar? cookies = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(body)
        };
        cookies?.Apply(request, client.BaseAddress!);
        var response = await client.SendAsync(request);
        cookies?.Capture(response, client.BaseAddress!);
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

    private static async Task<TestAppUser> SeedAsync(
        WebApplication app,
        string email,
        string? password = TestHelpers.DefaultPassword,
        bool confirmed = true,
        bool twoFactor = false)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = new TestAppUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = confirmed
        };
        var result = password is null
            ? await userManager.CreateAsync(user)
            : await userManager.CreateAsync(user, password);
        Assert.True(result.Succeeded, string.Join("; ", result.Errors.Select(error => error.Description)));
        if (twoFactor)
        {
            Assert.True((await userManager.ResetAuthenticatorKeyAsync(user)).Succeeded);
            Assert.True((await userManager.SetTwoFactorEnabledAsync(user, true)).Succeeded);
        }

        return user;
    }

    private static async Task LockAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        Assert.True((await userManager.SetLockoutEnabledAsync(user!, true)).Succeeded);
        Assert.True((await userManager.SetLockoutEndDateAsync(user!, DateTimeOffset.UtcNow.AddDays(1))).Succeeded);
    }

    private static async Task<List<EmailCodeEntity>> RowsAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        var normalizer = scope.ServiceProvider.GetRequiredService<ILookupNormalizer>();
        var hash = EmailCodeHasher.HashEmail(normalizer.NormalizeEmail(email.Trim())!);
        return await db.Set<EmailCodeEntity>().AsNoTracking()
            .Where(row => row.EmailHash == hash)
            .OrderBy(row => row.CreatedAt)
            .ThenBy(row => row.Id)
            .ToListAsync();
    }

    private static async Task<string> AuthenticatorKeyAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return (await userManager.GetAuthenticatorKeyAsync(user!))!;
    }

    private static async Task<string> RecoveryCodeAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        var codes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user!, 5);
        return codes!.First();
    }

    private static async Task<bool> RecoveryCodeStillValidAsync(WebApplication app, string email, string code)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        var result = await userManager.RedeemTwoFactorRecoveryCodeAsync(user!, code);
        return result.Succeeded;
    }

    private static async Task<int> RecoveryCodeCountAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return await userManager.CountRecoveryCodesAsync(user!);
    }

    private static async Task<int> AccessFailedCountAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return await userManager.GetAccessFailedCountAsync(user!);
    }

    private static async Task<bool> IsLockedOutAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return await userManager.IsLockedOutAsync(user!);
    }

    private static async Task<bool> IsConfirmedAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return await userManager.IsEmailConfirmedAsync(user!);
    }

    private static async Task<string?> StampAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return await userManager.GetSecurityStampAsync(user!);
    }

    private static async Task<bool> HasPasswordAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return await userManager.HasPasswordAsync(user!);
    }

    private static async Task<IList<UserLoginInfo>> LoginsAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return await userManager.GetLoginsAsync(user!);
    }

    private static async Task<IList<UserPasskeyInfo>> PasskeysAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return await userManager.GetPasskeysAsync(user!);
    }

    private static async Task AddLoginAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        var result = await userManager.AddLoginAsync(user!, new UserLoginInfo("google", Guid.NewGuid().ToString("N"), "Google"));
        Assert.True(result.Succeeded, string.Join("; ", result.Errors.Select(error => error.Description)));
    }

    private static async Task AddPasskeyAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        var passkey = new UserPasskeyInfo(
            [1, 2, 3, 4, 5, 6, 7, 8],
            [9, 8, 7],
            DateTimeOffset.UtcNow,
            0,
            [],
            false,
            false,
            false,
            [1],
            [2]);
        var result = await userManager.AddOrUpdatePasskeyAsync(user!, passkey);
        Assert.True(result.Succeeded, string.Join("; ", result.Errors.Select(error => error.Description)));
    }

    private sealed class EmailCodeHost : IAsyncDisposable
    {
        private readonly string _path;

        private EmailCodeHost(WebApplication app, string path, CapturingEmailSender mail, MutableClock clock, AuditLogger logs)
        {
            App = app;
            _path = path;
            Mail = mail;
            Clock = clock;
            Logs = logs;
            Client = app.GetTestClient();
        }

        public WebApplication App { get; }

        public HttpClient Client { get; }

        public CapturingEmailSender Mail { get; }

        public MutableClock Clock { get; }

        public AuditLogger Logs { get; }

        public static async Task<EmailCodeHost> StartAsync(
            Action<EmailCodeOptions>? configure = null,
            Action<IdentityOptions>? identity = null,
            IEmailCodeSender<TestAppUser>? sender = null,
            bool jwt = false,
            bool captureLogs = false,
            Action<IServiceCollection>? configureServices = null,
            bool useRateLimiter = true,
            Action<SqliteDbContextOptionsBuilder>? configureSqlite = null)
        {
            var path = Path.Combine(Path.GetTempPath(), $"ae-email-code-host-{Guid.NewGuid():N}.sqlite");
            var mail = new CapturingEmailSender();
            var clock = new MutableClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
            var logs = new AuditLogger();
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = Environments.Development
            });
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<TestDbContext>(options =>
                options.UseSqlite(
                    // Pooling races SQLite function registration when the attempt-cap barrier
                    // releases many connections at once (Error 5: unable to delete/modify user-function).
                    $"Data Source={path};Default Timeout=30;Pooling=False",
                    sqlite => configureSqlite?.Invoke(sqlite)));
            builder.Services.AddSingleton<IEmailSender<TestAppUser>>(mail);
            builder.Services.AddSingleton(sender ?? mail);
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
                    identity?.Invoke(options);
                })
                .AddEntityFrameworkStores<TestDbContext>()
                .AddDefaultTokenProviders();
            builder.Services.AddAuthorization();
            builder.Services.AddAntiforgery();
            builder.Services.AddCookieAuthEndpoints();
            builder.Services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>(options =>
            {
                options.SendsPerIpPerMinute = 100;
                configure?.Invoke(options);
            });
            if (jwt)
            {
                builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwtOptions =>
                {
                    jwtOptions.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
                });
                builder.Services.AddEmailCodeSignInCompleter<TestAppUser, JwtEmailCodeSignInCompleter<TestAppUser>>();
            }

            builder.Services.AddSingleton<TimeProvider>(clock);
            if (captureLogs)
            {
                builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ILoggerProvider>(logs));
                builder.Logging.AddFilter(EmailCodeLog.Category, LogLevel.Trace);
            }

            configureServices?.Invoke(builder.Services);

            var app = builder.Build();
            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                await db.Database.EnsureDeletedAsync();
                await db.Database.EnsureCreatedAsync();
                await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");
            }

            app.UseAuthentication();
            app.UseAuthorization();
            if (useRateLimiter)
            {
                app.UseRateLimiter();
            }

            app.UseAntiforgery();
            var identityGroup = app.MapGroup("/identity");
            identityGroup.MapIdentityManagementApi<TestAppUser>();
            identityGroup.MapCookieAuthEndpoints<TestAppUser>();
            identityGroup.MapEmailCodeEndpoints<TestAppUser>();
            app.MapGet("/test/reauth", () => Results.Ok()).RequireReauth();
            await app.StartAsync();
            return new EmailCodeHost(app, path, mail, clock, logs);
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

    private sealed class MutableClock : TimeProvider
    {
        private DateTimeOffset _utc;

        public MutableClock(DateTimeOffset utc)
        {
            _utc = utc;
        }

        public override DateTimeOffset GetUtcNow() => _utc;

        public void Advance(TimeSpan by) => _utc = _utc.Add(by);
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
            var header = Header(baseAddress);
            if (!string.IsNullOrEmpty(header))
            {
                request.Headers.TryAddWithoutValidation("Cookie", header);
            }
        }

        public string Header(Uri baseAddress) => _cookies.GetCookieHeader(baseAddress);
    }

    private sealed class SelectiveEmailCodeSender : IEmailCodeSender<TestAppUser>
    {
        public CapturingEmailSender Inner { get; } = new();

        public Task SendSignInCodeAsync(EmailCodeMessage<TestAppUser> message, CancellationToken cancellationToken = default)
        {
            Inner.SendSignInCodeAsync(message, cancellationToken);
            if (message.Email.Contains("throw", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("send failed");
            }

            return Task.CompletedTask;
        }
    }

    private sealed class StubEmailCodeSender : IEmailCodeSender<TestAppUser>
    {
        public Task SendSignInCodeAsync(EmailCodeMessage<TestAppUser> message, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class AuditLogger : ILoggerProvider
    {
        public List<string> Messages { get; } = [];

        public ILogger CreateLogger(string categoryName)
        {
            return new CategoryLogger(categoryName, Messages);
        }

        public void Dispose()
        {
        }

        private sealed class CategoryLogger : ILogger
        {
            private readonly string _category;
            private readonly List<string> _messages;

            public CategoryLogger(string category, List<string> messages)
            {
                _category = category;
                _messages = messages;
            }

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (!string.Equals(_category, EmailCodeLog.Category, StringComparison.Ordinal))
                {
                    return;
                }

                var text = eventId.Name + " " + formatter(state, exception);
                lock (_messages)
                {
                    _messages.Add(text);
                }
            }
        }
    }

    private sealed class TimingOutEmailCodeSender : IEmailCodeSender<TestAppUser>
    {
        public Task SendSignInCodeAsync(EmailCodeMessage<TestAppUser> message, CancellationToken cancellationToken = default)
        {
            throw new TaskCanceledException("smtp timeout");
        }
    }

    private sealed class PrefixLookupNormalizer : ILookupNormalizer
    {
        public string? NormalizeEmail(string? email)
        {
            return email is null ? null : "ee:" + email.Trim().ToUpperInvariant();
        }

        public string? NormalizeName(string? name)
        {
            return name?.ToUpperInvariant();
        }
    }

    private sealed class RetryingExecutionStrategy : ExecutionStrategy
    {
        public RetryingExecutionStrategy(ExecutionStrategyDependencies dependencies)
            : base(dependencies, maxRetryCount: 3, maxRetryDelay: TimeSpan.Zero)
        {
        }

        protected override bool ShouldRetryOn(Exception exception) => false;
    }

    private sealed class SerializationFailureStore : IEmailCodeStore
    {
        public int IssueCalls { get; private set; }

        public Task<EmailCodeIssueResult> IssueAsync(
            string email,
            string? userId,
            string? securityStamp,
            EmailCodeRowPurpose purpose,
            bool rememberSignupEmail = false,
            CancellationToken cancellationToken = default)
        {
            IssueCalls++;
            throw EmailCodeFailureExceptions.SqlDeadlock();
        }

        public Task<EmailCodeEntry?> FindLiveByEmailAsync(
            string email,
            EmailCodeRowPurpose purpose,
            string? userId = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult<EmailCodeEntry?>(null);

        public Task<EmailCodeEntry?> FindLiveByLinkTokenAsync(string token, CancellationToken cancellationToken = default)
            => Task.FromResult<EmailCodeEntry?>(null);

        public bool CodeMatches(EmailCodeEntry row, string submittedCode) => false;

        public Task<bool> TryReserveAttemptAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
            => Task.FromResult(false);

        public Task<bool> TryReleaseAttemptAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
            => Task.FromResult(false);

        public Task<bool> TryConsumeAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
            => Task.FromResult(false);

        public Task<bool> TryConsumeReservedAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
            => Task.FromResult(false);

        public Task<bool> TryUnconsumeAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
            => Task.FromResult(false);

        public Task<bool> IsWithinResendCooldownAsync(
            string email,
            EmailCodeRowPurpose purpose,
            CancellationToken cancellationToken = default)
            => Task.FromResult(false);

        public Task<bool> HasReachedSendCapAsync(
            string email,
            EmailCodeRowPurpose purpose,
            CancellationToken cancellationToken = default)
            => Task.FromResult(false);
    }

    private sealed class CompareCounter
    {
        private int _compares;

        public int Compares => _compares;

        public void Increment() => Interlocked.Increment(ref _compares);
    }

    private sealed class GatedEmailCodeStore : IEmailCodeStore
    {
        private readonly EmailCodeStore<TestDbContext> _inner;
        private readonly CompareCounter _compares;
        private readonly Barrier _afterLoad;
        private readonly EmailCodeRowPurpose? _gatePurpose;

        public GatedEmailCodeStore(
            EmailCodeStore<TestDbContext> inner,
            CompareCounter compares,
            Barrier afterLoad,
            EmailCodeRowPurpose? gatePurpose = null)
        {
            _inner = inner;
            _compares = compares;
            _afterLoad = afterLoad;
            _gatePurpose = gatePurpose;
        }

        public Task<EmailCodeIssueResult> IssueAsync(
            string email,
            string? userId,
            string? securityStamp,
            EmailCodeRowPurpose purpose,
            bool rememberSignupEmail = false,
            CancellationToken cancellationToken = default)
            => _inner.IssueAsync(email, userId, securityStamp, purpose, rememberSignupEmail, cancellationToken);

        public async Task<EmailCodeEntry?> FindLiveByEmailAsync(
            string email,
            EmailCodeRowPurpose purpose,
            string? userId = null,
            CancellationToken cancellationToken = default)
        {
            var row = await _inner.FindLiveByEmailAsync(email, purpose, userId, cancellationToken);
            if (row is not null && Gates(row))
            {
                Assert.True(_afterLoad.SignalAndWait(TimeSpan.FromSeconds(30)));
            }

            return row;
        }

        public async Task<EmailCodeEntry?> FindLiveByLinkTokenAsync(string token, CancellationToken cancellationToken = default)
        {
            var row = await _inner.FindLiveByLinkTokenAsync(token, cancellationToken);
            if (row is not null && Gates(row))
            {
                Assert.True(_afterLoad.SignalAndWait(TimeSpan.FromSeconds(30)));
            }

            return row;
        }

        private bool Gates(EmailCodeEntry row) => _gatePurpose is null || row.Purpose == _gatePurpose;

        public bool CodeMatches(EmailCodeEntry row, string submittedCode)
        {
            if (_gatePurpose is null || row.Purpose == _gatePurpose)
            {
                _compares.Increment();
            }

            return _inner.CodeMatches(row, submittedCode);
        }

        public Task<bool> TryReserveAttemptAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
            => _inner.TryReserveAttemptAsync(row, cancellationToken);

        public Task<bool> TryReleaseAttemptAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
            => _inner.TryReleaseAttemptAsync(row, cancellationToken);

        public Task<bool> TryConsumeAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
            => _inner.TryConsumeAsync(row, cancellationToken);

        public Task<bool> TryConsumeReservedAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
            => _inner.TryConsumeReservedAsync(row, cancellationToken);

        public Task<bool> TryUnconsumeAsync(EmailCodeEntry row, CancellationToken cancellationToken = default)
            => _inner.TryUnconsumeAsync(row, cancellationToken);

        public Task<bool> IsWithinResendCooldownAsync(
            string email,
            EmailCodeRowPurpose purpose,
            CancellationToken cancellationToken = default)
            => _inner.IsWithinResendCooldownAsync(email, purpose, cancellationToken);

        public Task<bool> HasReachedSendCapAsync(
            string email,
            EmailCodeRowPurpose purpose,
            CancellationToken cancellationToken = default)
            => _inner.HasReachedSendCapAsync(email, purpose, cancellationToken);
    }

    private enum SignupCreateMode
    {
        UniqueConflict,
        RequiredColumn
    }

    private sealed class SignupCreateGate
    {
        private int _claimed;

        public SignupCreateMode Mode { get; init; }

        public bool TwoFactor { get; init; }

        public string? Email { get; set; }

        public string? CreatedUserId { get; set; }

        public bool Claimed => Volatile.Read(ref _claimed) == 1;

        public bool TryClaim(string? email)
        {
            if (email is null || !string.Equals(email, Email, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return Interlocked.Exchange(ref _claimed, 1) == 0;
        }
    }

    private sealed class ConflictSignupUserManager : UserManager<TestAppUser>
    {
        private readonly IServiceProvider _services;

        public ConflictSignupUserManager(
            IUserStore<TestAppUser> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<TestAppUser> passwordHasher,
            IEnumerable<IUserValidator<TestAppUser>> userValidators,
            IEnumerable<IPasswordValidator<TestAppUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<TestAppUser>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            _services = services;
        }

        public override async Task<IdentityResult> CreateAsync(TestAppUser user)
        {
            var gate = _services.GetRequiredService<SignupCreateGate>();
            if (!gate.TryClaim(user.Email))
            {
                return await base.CreateAsync(user);
            }

            if (gate.Mode == SignupCreateMode.RequiredColumn)
            {
                var context = (DbContext)Store.GetType().GetProperty("Context")!.GetValue(Store)!;
                context.Add(user);
                throw new DbUpdateException(
                    "required column",
                    new InvalidOperationException("NOT NULL constraint failed"));
            }

            await using var scope = _services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var raced = new TestAppUser
            {
                UserName = user.Email,
                Email = user.Email,
                EmailConfirmed = true
            };
            var created = await users.CreateAsync(raced, TestHelpers.DefaultPassword);
            if (!created.Succeeded)
            {
                throw new InvalidOperationException(string.Join("; ", created.Errors.Select(error => error.Description)));
            }

            if (gate.TwoFactor)
            {
                var key = await users.ResetAuthenticatorKeyAsync(raced);
                var enabled = await users.SetTwoFactorEnabledAsync(raced, true);
                if (!key.Succeeded || !enabled.Succeeded)
                {
                    throw new InvalidOperationException("Could not enable two-factor authentication.");
                }
            }

            gate.CreatedUserId = raced.Id;
            return await base.CreateAsync(user);
        }
    }

    private sealed class FailingPasswordUserManager : UserManager<TestAppUser>
    {
        public FailingPasswordUserManager(
            IUserStore<TestAppUser> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<TestAppUser> passwordHasher,
            IEnumerable<IUserValidator<TestAppUser>> userValidators,
            IEnumerable<IPasswordValidator<TestAppUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<TestAppUser>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
        }

        public override Task<IdentityResult> RemovePasswordAsync(TestAppUser user)
        {
            return Task.FromResult(IdentityResult.Failed(ErrorDescriber.PasswordMismatch()));
        }
    }

    private sealed class FailingRecoveryUserManager : UserManager<TestAppUser>
    {
        public FailingRecoveryUserManager(
            IUserStore<TestAppUser> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<TestAppUser> passwordHasher,
            IEnumerable<IUserValidator<TestAppUser>> userValidators,
            IEnumerable<IPasswordValidator<TestAppUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<TestAppUser>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
        }

        public override Task<IdentityResult> RedeemTwoFactorRecoveryCodeAsync(TestAppUser user, string code)
        {
            return Task.FromResult(IdentityResult.Failed(ErrorDescriber.RecoveryCodeRedemptionFailed()));
        }
    }

    private sealed class UnusedEmailCodeSignInCompleter : IEmailCodeSignInCompleter<TestAppUser>
    {
        public Task<IResult> CompleteAsync(
            HttpContext httpContext,
            TestAppUser user,
            EmailCodeSignInContext context,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class UnmappedEmailCodeDbContext : DbContext
    {
        public UnmappedEmailCodeDbContext(DbContextOptions<UnmappedEmailCodeDbContext> options)
            : base(options)
        {
        }
    }

    private sealed class MappedEmailCodeDbContext : DbContext
    {
        public MappedEmailCodeDbContext(DbContextOptions<MappedEmailCodeDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.UseEmailCodes();
        }
    }
}
