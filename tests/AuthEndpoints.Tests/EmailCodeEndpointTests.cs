using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.ReAuth;
using EmailCodeEntity = AuthEndpoints.EmailCode.EmailCode;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
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

namespace AuthEndpoints.Tests;

public class EmailCodeEndpointTests
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
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        foreach (var response in new[] { unknownResponse, lockedResponse, cooled, rejectedResponse, threw })
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(body, await response.Content.ReadAsStringAsync());
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
            using (var scope = host.App.Services.CreateScope())
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
                var store = scope.ServiceProvider.GetRequiredService<IEmailCodeStore>();
                var user = await userManager.FindByEmailAsync(email);
                var issued = await store.IssueAsync(email, user!.Id, await userManager.GetSecurityStampAsync(user));
                code = issued.Code;
            }

            var response = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code });
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("Unauthorized", await ProblemTitleAsync(response));
            Assert.NotNull((await RowsAsync(host.App, email)).OrderByDescending(row => row.CreatedAt).First().ConsumedAt);
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
    }

    private static WebApplication BuildProductionHost(IEmailCodeSender<TestAppUser>? sender, bool developmentSender, bool requireSender)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Production
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
            options.EmailCode.Configure = emailCode => emailCode.RequireSenderInProduction = requireSender;
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

    private static List<string> Codes(CapturingEmailSender mail, string email)
    {
        return mail.Snapshot()
            .Where(item => item.Kind == "email-code" && item.Email == email)
            .Select(item => item.Body)
            .ToList();
    }

    private static string UniqueEmail(string label) => $"{label}-{Guid.NewGuid():N}@test.local";

    private static string WrongCode(string code)
    {
        var wrong = new string('0', code.Length);
        return wrong == code ? new string('1', code.Length) : wrong;
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
        var hash = EmailCodeHasher.HashEmail(EmailCodeHasher.NormalizeEmail(email));
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
            bool captureLogs = false)
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
                options.UseSqlite($"Data Source={path};Default Timeout=30"));
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
            app.UseRateLimiter();
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
            var header = _cookies.GetCookieHeader(baseAddress);
            if (!string.IsNullOrEmpty(header))
            {
                request.Headers.TryAddWithoutValidation("Cookie", header);
            }
        }
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
}
