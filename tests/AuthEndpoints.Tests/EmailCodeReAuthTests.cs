using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints.EmailCode;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Tests;

public partial class EmailCodeEndpointTests
{
    private const string ExactlyOneProof =
        "Provide exactly one of Password, TwoFactorCode, TwoFactorRecoveryCode, CredentialJson, or EmailCode.";

    [Fact]
    public async Task ConfirmIdentity_RejectsSignInCode_AndVerifyRejectsReAuthCode()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("isolate");
        await SeedAsync(host.App, email, password: null);
        var jar = await SignInEmailCodeAsync(host, email);
        host.Clock.Advance(TimeSpan.FromSeconds(61));

        Assert.Equal(HttpStatusCode.OK, (await PostAsync(host.Client, "/identity/emailCode/send", new { email })).StatusCode);
        var signInCode = CodeFor(host.Mail, email, EmailCodePurpose.SignIn);
        var rejected = await ConfirmAsync(host, jar, new { emailCode = signInCode });
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        var signInRow = (await RowsAsync(host.App, email)).Single(row => row.Purpose == EmailCodeRowPurpose.SignIn && row.ConsumedAt is null);
        Assert.Equal(0, signInRow.Attempts);

        var sent = await SendReAuthAsync(host, jar);
        Assert.Equal(HttpStatusCode.OK, sent.StatusCode);
        var (expires, resend) = await ReadSendAsync(sent);
        Assert.Equal(300, expires);
        Assert.Equal(60, resend);
        var reauthMail = MailForPurpose(host.Mail, email, EmailCodePurpose.ReAuth);
        Assert.Null(reauthMail.LinkUrl);
        var reauthRow = (await RowsAsync(host.App, email)).Single(row => row.Purpose == EmailCodeRowPurpose.ReAuth);
        Assert.Null(reauthRow.LinkTokenHash);
        Assert.Equal(0, reauthRow.Attempts);

        var verify = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = reauthMail.Body });
        Assert.Equal(HttpStatusCode.Unauthorized, verify.StatusCode);
        reauthRow = (await RowsAsync(host.App, email)).Single(row => row.Id == reauthRow.Id);
        Assert.Null(reauthRow.ConsumedAt);
        Assert.Equal(0, reauthRow.Attempts);

        var confirmed = await ConfirmAsync(host, jar, new { emailCode = reauthMail.Body });
        await AssertStatusAsync(confirmed, HttpStatusCode.OK);
        var signedIn = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = signInCode });
        await AssertStatusAsync(signedIn, HttpStatusCode.OK);
    }

    [Fact]
    public async Task ConfirmIdentity_RejectsAnotherUsersCode()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var victim = UniqueEmail("victim");
        var other = UniqueEmail("other");
        await SeedAsync(host.App, victim, password: null);
        await SeedAsync(host.App, other, password: null);
        var victimJar = await SignInEmailCodeAsync(host, victim);
        var otherJar = await SignInEmailCodeAsync(host, other);

        var sent = await SendReAuthAsync(host, victimJar);
        await AssertStatusAsync(sent, HttpStatusCode.OK);
        var code = CodeFor(host.Mail, victim, EmailCodePurpose.ReAuth);
        var stolen = await ConfirmAsync(host, otherJar, new { emailCode = code });
        Assert.Equal(HttpStatusCode.Unauthorized, stolen.StatusCode);
        var row = (await RowsAsync(host.App, victim)).Single(item => item.Purpose == EmailCodeRowPurpose.ReAuth);
        Assert.Null(row.ConsumedAt);
        Assert.Equal(0, row.Attempts);

        var accepted = await ConfirmAsync(host, victimJar, new { emailCode = code });
        await AssertStatusAsync(accepted, HttpStatusCode.OK);
        Assert.NotNull((await RowsAsync(host.App, victim)).Single(item => item.Id == row.Id).ConsumedAt);
    }

    [Fact]
    public async Task ConfirmIdentity_SecurityStampChange_RejectsCodeWithoutReserving()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("stamp");
        await SeedAsync(host.App, email, password: null);
        var jar = await SignInEmailCodeAsync(host, email);
        var sent = await SendReAuthAsync(host, jar);
        await AssertStatusAsync(sent, HttpStatusCode.OK);
        var code = CodeFor(host.Mail, email, EmailCodePurpose.ReAuth);
        var before = await StampAsync(host.App, email);
        await UpdateStampAsync(host.App, email);
        Assert.NotEqual(before, await StampAsync(host.App, email));

        var info = await GetAsync(host.Client, "/identity/manage/info", jar);
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);
        var rejected = await ConfirmAsync(host, jar, new { emailCode = code });
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        var row = (await RowsAsync(host.App, email)).Single(item => item.Purpose == EmailCodeRowPurpose.ReAuth);
        Assert.Equal(0, row.Attempts);
        Assert.Null(row.ConsumedAt);
        Assert.Equal(before, row.SecurityStamp);
    }

    [Fact]
    public async Task ConfirmIdentity_ParallelAttemptCap_ComparesAtMostMaxAttempts()
    {
        const int maxAttempts = 5;
        var counter = new CompareCounter();
        var loaded = new Barrier(21);
        await using var host = await EmailCodeHost.StartAsync(
            options => options.MaxAttempts = maxAttempts,
            configureServices: services => services.AddScoped<IEmailCodeStore>(sp => new GatedEmailCodeStore(
                CreateStore(sp),
                counter,
                loaded,
                EmailCodeRowPurpose.ReAuth)),
            useRateLimiter: false);
        var email = UniqueEmail("reauth-cap");
        await SeedAsync(host.App, email, password: null);
        var jar = await SignInEmailCodeAsync(host, email);
        var sent = await SendReAuthAsync(host, jar);
        await AssertStatusAsync(sent, HttpStatusCode.OK);
        var code = CodeFor(host.Mail, email, EmailCodePurpose.ReAuth);
        var wrong = WrongCode(code);
        var csrf = await CsrfAsync(host.Client, jar);
        var cookies = jar.Header(host.Client.BaseAddress!);

        var attempts = new List<Task<HttpResponseMessage>>();
        for (var i = 0; i < 20; i++)
        {
            attempts.Add(PostHeadersAsync(host.Client, "/identity/confirmIdentity", new { emailCode = wrong }, cookies, csrf));
        }

        attempts.Add(PostHeadersAsync(host.Client, "/identity/confirmIdentity", new { emailCode = code }, cookies, csrf));
        var results = await Task.WhenAll(attempts);
        await AssertNoServerErrorAsync(results);
        var unexpected = results.Where(response => response.StatusCode is not HttpStatusCode.OK and not HttpStatusCode.Unauthorized).ToArray();
        Assert.True(unexpected.Length == 0, string.Join(", ", unexpected.Select(response => (int)response.StatusCode)));
        Assert.InRange(counter.Compares, 1, maxAttempts);
        Assert.True(results.Count(response => response.StatusCode == HttpStatusCode.OK) <= 1);

        var followUp = await ConfirmAsync(host, jar, new { emailCode = code });
        Assert.Equal(HttpStatusCode.Unauthorized, followUp.StatusCode);
        var row = (await RowsAsync(host.App, email)).Single(item => item.Purpose == EmailCodeRowPurpose.ReAuth);
        if (row.ConsumedAt is null)
        {
            Assert.Equal(maxAttempts, row.Attempts);
            Assert.DoesNotContain(results, response => response.StatusCode == HttpStatusCode.OK);
        }
    }

    [Fact]
    public async Task ConfirmIdentity_EmailCode_IsSingleUse_AndExpiresAfterFiveMinutes()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var once = UniqueEmail("once");
        await SeedAsync(host.App, once, password: null);
        var onceJar = await SignInEmailCodeAsync(host, once);
        var sent = await SendReAuthAsync(host, onceJar);
        await AssertStatusAsync(sent, HttpStatusCode.OK);
        var code = CodeFor(host.Mail, once, EmailCodePurpose.ReAuth);
        var wrong = await ConfirmAsync(host, onceJar, new { emailCode = WrongCode(code) });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(1, (await RowsAsync(host.App, once)).Single(row => row.Purpose == EmailCodeRowPurpose.ReAuth).Attempts);
        Assert.Equal(1, await AccessFailedCountAsync(host.App, once));

        var accepted = await ConfirmAsync(host, onceJar, new { emailCode = code });
        await AssertStatusAsync(accepted, HttpStatusCode.OK);
        AssertNoSession(accepted);
        var replay = await ConfirmAsync(host, onceJar, new { emailCode = code });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.NotNull((await RowsAsync(host.App, once)).Single(row => row.Purpose == EmailCodeRowPurpose.ReAuth).ConsumedAt);

        var email = UniqueEmail("expire");
        await SeedAsync(host.App, email, password: null);
        var jar = await SignInEmailCodeAsync(host, email);
        host.Clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(host.Client, "/identity/emailCode/send", new { email })).StatusCode);
        var signInCode = CodeFor(host.Mail, email, EmailCodePurpose.SignIn);
        var reauth = await SendReAuthAsync(host, jar);
        await AssertStatusAsync(reauth, HttpStatusCode.OK);
        var reauthCode = CodeFor(host.Mail, email, EmailCodePurpose.ReAuth);
        host.Clock.Advance(TimeSpan.FromMinutes(6));

        var expired = await ConfirmAsync(host, jar, new { emailCode = reauthCode });
        Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
        var expiredRow = (await RowsAsync(host.App, email)).Single(row => row.Purpose == EmailCodeRowPurpose.ReAuth);
        Assert.Equal(0, expiredRow.Attempts);
        Assert.Null(expiredRow.ConsumedAt);
        var stillValid = await PostAsync(host.Client, "/identity/emailCode/verify", new { email, code = signInCode });
        await AssertStatusAsync(stillValid, HttpStatusCode.OK);
    }

    [Fact]
    public async Task ReAuthSend_CooldownAndCap_ArePerPurpose()
    {
        await using (var host = await EmailCodeHost.StartAsync())
        {
            var email = UniqueEmail("cooldown");
            await SeedAsync(host.App, email, password: null);
            var jar = await SignInEmailCodeAsync(host, email);
            var reauth = await SendReAuthAsync(host, jar);
            await AssertStatusAsync(reauth, HttpStatusCode.OK);
            Assert.Equal(EmailCodePurpose.ReAuth, MailForPurpose(host.Mail, email, EmailCodePurpose.ReAuth).Purpose);

            var signInAgain = await PostAsync(host.Client, "/identity/emailCode/send", new { email });
            Assert.Equal(HttpStatusCode.OK, signInAgain.StatusCode);
            var reauthAgain = await SendReAuthAsync(host, jar);
            Assert.Equal(HttpStatusCode.OK, reauthAgain.StatusCode);
            Assert.Single(host.Mail.Snapshot(), item => item.Email == email && item.Purpose == EmailCodePurpose.SignIn);
            Assert.Single(host.Mail.Snapshot(), item => item.Email == email && item.Purpose == EmailCodePurpose.ReAuth);
            var rows = await RowsAsync(host.App, email);
            Assert.Null(rows.Single(row => row.Purpose == EmailCodeRowPurpose.SignIn).SupersededAt);
            Assert.Null(rows.Single(row => row.Purpose == EmailCodeRowPurpose.ReAuth).SupersededAt);
        }

        await using var capped = await EmailCodeHost.StartAsync(options =>
        {
            options.ResendCooldown = TimeSpan.Zero;
            options.MaxSendsPerEmail = 1;
        });
        var cappedEmail = UniqueEmail("cap");
        await SeedAsync(capped.App, cappedEmail, password: null);
        var cappedJar = await SignInEmailCodeAsync(capped, cappedEmail);
        var cappedReauth = await SendReAuthAsync(capped, cappedJar);
        await AssertStatusAsync(cappedReauth, HttpStatusCode.OK);
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(capped.Client, "/identity/emailCode/send", new { email = cappedEmail })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendReAuthAsync(capped, cappedJar)).StatusCode);
        Assert.Single(capped.Mail.Snapshot(), item => item.Email == cappedEmail && item.Purpose == EmailCodePurpose.SignIn);
        Assert.Single(capped.Mail.Snapshot(), item => item.Email == cappedEmail && item.Purpose == EmailCodePurpose.ReAuth);
    }

    [Fact]
    public async Task EmailCodeProof_RefusedWhenAStrongerFactorExists()
    {
        await using (var host = await EmailCodeHost.StartAsync())
        {
            var email = UniqueEmail("password");
            await SeedAsync(host.App, email);
            var jar = await LoginAsync(host, email);
            await AssertUnavailableAsync(host, jar, email);
            var confirm = await ConfirmAsync(host, jar, new { emailCode = "000000" });
            Assert.Equal(HttpStatusCode.BadRequest, confirm.StatusCode);
            Assert.Equal("EmailCodeProofUnavailable", await ProblemTitleAsync(confirm));
            var password = await ConfirmAsync(host, jar, new { password = TestHelpers.DefaultPassword });
            await AssertStatusAsync(password, HttpStatusCode.OK);
        }

        await using (var host = await EmailCodeHost.StartAsync(options => options.RequireTwoFactor = false))
        {
            var email = UniqueEmail("totp");
            await SeedAsync(host.App, email, password: null, twoFactor: true);
            var jar = await SignInEmailCodeAsync(host, email);
            await AssertUnavailableAsync(host, jar, email);
        }

        await using (var host = await EmailCodeHost.StartAsync())
        {
            var email = UniqueEmail("passkey");
            await SeedAsync(host.App, email, password: null);
            await AddPasskeyAsync(host.App, email);
            var jar = await SignInEmailCodeAsync(host, email);
            await AssertUnavailableAsync(host, jar, email);
        }

        await using (var host = await EmailCodeHost.StartAsync(identity: options => options.SignIn.RequireConfirmedAccount = false))
        {
            var email = UniqueEmail("unconfirmed");
            await SeedAsync(host.App, email, confirmed: false);
            var jar = await LoginAsync(host, email);
            await AssertUnavailableAsync(host, jar, email);
        }

        await using (var host = await EmailCodeHost.StartAsync(options => options.ReAuth.Enabled = false))
        {
            var email = UniqueEmail("disabled");
            await SeedAsync(host.App, email, password: null);
            var jar = await SignInEmailCodeAsync(host, email);
            await AssertUnavailableAsync(host, jar, email);
        }
    }

    [Fact]
    public async Task EmailCodeProof_AllowsExternalOnlyUsers_AndAlwaysAllowsPasswordUsers()
    {
        await using (var host = await EmailCodeHost.StartAsync())
        {
            var email = UniqueEmail("external");
            await SeedAsync(host.App, email, password: null);
            await AddLoginAsync(host.App, email);
            var jar = await SignInEmailCodeAsync(host, email);
            Assert.True(await EmailCodeOfferedAsync(host, jar));
            Assert.NotEmpty(await LoginsAsync(host.App, email));
            Assert.False(await HasPasswordAsync(host.App, email));
            var sent = await SendReAuthAsync(host, jar);
            await AssertStatusAsync(sent, HttpStatusCode.OK);
            var confirmed = await ConfirmAsync(host, jar, new { emailCode = CodeFor(host.Mail, email, EmailCodePurpose.ReAuth) });
            await AssertStatusAsync(confirmed, HttpStatusCode.OK);
            AssertNoSession(confirmed);
            Assert.Equal(HttpStatusCode.OK, (await GetAsync(host.Client, "/test/reauth", jar)).StatusCode);
        }

        await using var always = await EmailCodeHost.StartAsync(options =>
            options.ReAuth.Availability = EmailCodeReAuthAvailability.Always);
        var passwordEmail = UniqueEmail("always");
        await SeedAsync(always.App, passwordEmail);
        var passwordJar = await LoginAsync(always, passwordEmail);
        Assert.True(await EmailCodeOfferedAsync(always, passwordJar));
        var alwaysSent = await SendReAuthAsync(always, passwordJar);
        await AssertStatusAsync(alwaysSent, HttpStatusCode.OK);
        var alwaysConfirmed = await ConfirmAsync(
            always,
            passwordJar,
            new { emailCode = CodeFor(always.Mail, passwordEmail, EmailCodePurpose.ReAuth) });
        await AssertStatusAsync(alwaysConfirmed, HttpStatusCode.OK);
    }

    [Fact]
    public async Task EmailCodeOnlyUser_StepsUpEnablesTwoFactor_ThenProofIsUnavailable()
    {
        await using var host = await EmailCodeHost.StartAsync(options => options.AllowSignUp = true);
        var email = UniqueEmail("e2e");
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(host.Client, "/identity/emailCode/send", new { email })).StatusCode);
        var jar = new CookieJar();
        var verify = await PostAsync(
            host.Client,
            "/identity/emailCode/verify?useSessionCookies=true",
            new { email, code = CodeFor(host.Mail, email, EmailCodePurpose.SignUp) },
            jar);
        await AssertStatusAsync(verify, HttpStatusCode.OK);
        Assert.Contains(".AspNetCore.Identity.Application", SetCookie(verify), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, (await GetAsync(host.Client, "/identity/manage/info", jar)).StatusCode);
        Assert.True(await EmailCodeOfferedAsync(host, jar));

        var sent = await SendReAuthAsync(host, jar);
        await AssertStatusAsync(sent, HttpStatusCode.OK);
        var mail = MailForPurpose(host.Mail, email, EmailCodePurpose.ReAuth);
        Assert.Null(mail.LinkUrl);
        var row = (await RowsAsync(host.App, email)).Single(item => item.Purpose == EmailCodeRowPurpose.ReAuth);
        Assert.False(string.IsNullOrEmpty(row.UserId));
        Assert.False(string.IsNullOrEmpty(row.SecurityStamp));
        Assert.Null(row.LinkTokenHash);

        var confirmed = await ConfirmAsync(host, jar, new { emailCode = mail.Body });
        await AssertStatusAsync(confirmed, HttpStatusCode.OK);
        AssertNoSession(confirmed);
        var token = await ReadReauthTokenAsync(confirmed);
        Assert.Equal(HttpStatusCode.OK, (await GetAsync(host.Client, "/test/reauth", jar)).StatusCode);

        var probe = await PostCsrfAsync(host.Client, "/identity/manage/2fa", new { }, jar, await CsrfAsync(host.Client, jar));
        await AssertStatusAsync(probe, HttpStatusCode.OK);
        using var probeDoc = JsonDocument.Parse(await probe.Content.ReadAsStringAsync());
        var sharedKey = TestHelpers.TryGetString(probeDoc.RootElement, "sharedKey", "SharedKey");
        Assert.False(string.IsNullOrWhiteSpace(sharedKey));

        host.Clock.Advance(TimeSpan.FromSeconds(61));
        var again = await SendReAuthAsync(host, jar);
        await AssertStatusAsync(again, HttpStatusCode.OK);
        var stepped = await ConfirmAsync(host, jar, new { emailCode = CodeFor(host.Mail, email, EmailCodePurpose.ReAuth) });
        await AssertStatusAsync(stepped, HttpStatusCode.OK);

        var enable = await PostCsrfAsync(
            host.Client,
            "/identity/manage/2fa",
            new { enable = true, twoFactorCode = TotpHelper.GenerateCode(sharedKey!) },
            jar,
            await CsrfAsync(host.Client, jar));
        await AssertStatusAsync(enable, HttpStatusCode.OK);
        Assert.False(await EmailCodeOfferedAsync(host, jar));
        var before = (await RowsAsync(host.App, email)).Count(item => item.Purpose == EmailCodeRowPurpose.ReAuth);
        var unavailable = await SendReAuthAsync(host, jar);
        Assert.Equal(HttpStatusCode.BadRequest, unavailable.StatusCode);
        Assert.Equal("EmailCodeProofUnavailable", await ProblemTitleAsync(unavailable));
        Assert.Equal(before, (await RowsAsync(host.App, email)).Count(item => item.Purpose == EmailCodeRowPurpose.ReAuth));
        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public async Task Send_IsLimitedToThreePerMinutePerUser()
    {
        await using var host = await EmailCodeHost.StartAsync(options =>
        {
            options.ResendCooldown = TimeSpan.Zero;
            options.MaxSendsPerEmail = 10;
        });
        var first = UniqueEmail("limit-a");
        var second = UniqueEmail("limit-b");
        await SeedAsync(host.App, first, password: null);
        await SeedAsync(host.App, second, password: null);
        var firstJar = await SignInEmailCodeAsync(host, first);
        var secondJar = await SignInEmailCodeAsync(host, second);

        for (var i = 0; i < 3; i++)
        {
            var ok = await SendReAuthAsync(host, firstJar);
            await AssertStatusAsync(ok, HttpStatusCode.OK);
        }

        var blocked = await SendReAuthAsync(host, firstJar);
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        var other = await SendReAuthAsync(host, secondJar);
        await AssertStatusAsync(other, HttpStatusCode.OK);
        Assert.Equal(3, (await RowsAsync(host.App, first)).Count(row => row.Purpose == EmailCodeRowPurpose.ReAuth));
    }

    [Fact]
    public async Task ConfirmIdentity_RequiresExactlyOneProof()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("proofs");
        await SeedAsync(host.App, email);
        var jar = await LoginAsync(host, email);
        var none = await ConfirmAsync(host, jar, new { });
        Assert.Equal(HttpStatusCode.BadRequest, none.StatusCode);
        Assert.Equal(ExactlyOneProof, JsonSerializer.Deserialize<string>(await none.Content.ReadAsStringAsync()));
        var both = await ConfirmAsync(host, jar, new { password = TestHelpers.DefaultPassword, emailCode = "000000" });
        Assert.Equal(HttpStatusCode.BadRequest, both.StatusCode);
        Assert.Equal(ExactlyOneProof, JsonSerializer.Deserialize<string>(await both.Content.ReadAsStringAsync()));

        var anonymousJar = new CookieJar();
        var anonymous = await PostCsrfAsync(
            host.Client,
            "/identity/confirmIdentity/emailCode/send",
            new { },
            anonymousJar,
            await CsrfAsync(host.Client, anonymousJar));
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }

    [Fact]
    public async Task BearerConfirm_ReturnsReauthTokenWithoutCookieOrAccessToken()
    {
        await using var host = await EmailCodeHost.StartAsync();
        var email = UniqueEmail("bearer-reauth");
        await SeedAsync(host.App, email, password: null);
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(host.Client, "/identity/emailCode/send", new { email })).StatusCode);
        var verify = await PostAsync(
            host.Client,
            "/identity/emailCode/verify",
            new { email, code = CodeFor(host.Mail, email, EmailCodePurpose.SignIn) });
        await AssertStatusAsync(verify, HttpStatusCode.OK);
        using var verifyDoc = JsonDocument.Parse(await verify.Content.ReadAsStringAsync());
        var accessToken = TestHelpers.TryGetString(verifyDoc.RootElement, "accessToken", "AccessToken");
        Assert.False(string.IsNullOrWhiteSpace(accessToken));
        Assert.DoesNotContain(".AspNetCore.Identity.Application", SetCookie(verify), StringComparison.Ordinal);

        var sent = await PostBearerAsync(host.Client, "/identity/confirmIdentity/emailCode/send", new { }, accessToken!);
        await AssertStatusAsync(sent, HttpStatusCode.OK);
        var confirmed = await PostBearerAsync(
            host.Client,
            "/identity/confirmIdentity",
            new { emailCode = CodeFor(host.Mail, email, EmailCodePurpose.ReAuth) },
            accessToken!);
        await AssertStatusAsync(confirmed, HttpStatusCode.OK);
        await ReadReauthTokenAsync(confirmed);
        var body = await confirmed.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.False(doc.RootElement.TryGetProperty("accessToken", out _) || doc.RootElement.TryGetProperty("AccessToken", out _));
        var cookies = SetCookie(confirmed);
        Assert.DoesNotContain("AuthEndpoints.ReAuth", cookies, StringComparison.Ordinal);
        Assert.DoesNotContain(".AspNetCore.Identity.Application", cookies, StringComparison.Ordinal);
    }

    private static async Task AssertUnavailableAsync(EmailCodeHost host, CookieJar jar, string email)
    {
        Assert.False(await EmailCodeOfferedAsync(host, jar));
        var before = (await RowsAsync(host.App, email)).Count(row => row.Purpose == EmailCodeRowPurpose.ReAuth);
        var sent = await SendReAuthAsync(host, jar);
        Assert.Equal(HttpStatusCode.BadRequest, sent.StatusCode);
        Assert.Equal("EmailCodeProofUnavailable", await ProblemTitleAsync(sent));
        Assert.Equal(before, (await RowsAsync(host.App, email)).Count(row => row.Purpose == EmailCodeRowPurpose.ReAuth));
    }

    private static void AssertNoSession(HttpResponseMessage response)
    {
        var cookies = SetCookie(response);
        Assert.Contains("AuthEndpoints.ReAuth", cookies, StringComparison.Ordinal);
        Assert.DoesNotContain(".AspNetCore.Identity.Application", cookies, StringComparison.Ordinal);
    }

    private static async Task<CookieJar> SignInEmailCodeAsync(EmailCodeHost host, string email)
    {
        var sent = await PostAsync(host.Client, "/identity/emailCode/send", new { email });
        await AssertStatusAsync(sent, HttpStatusCode.OK);
        var jar = new CookieJar();
        var verify = await PostAsync(
            host.Client,
            "/identity/emailCode/verify?useSessionCookies=true",
            new { email, code = CodeFor(host.Mail, email, EmailCodePurpose.SignIn) },
            jar);
        await AssertStatusAsync(verify, HttpStatusCode.OK);
        return jar;
    }

    private static async Task<CookieJar> LoginAsync(EmailCodeHost host, string email)
    {
        var jar = new CookieJar();
        var response = await PostAsync(
            host.Client,
            "/identity/login",
            new { email, password = TestHelpers.DefaultPassword },
            jar);
        Assert.True(
            response.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent,
            $"{(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        return jar;
    }

    private static async Task<bool> EmailCodeOfferedAsync(EmailCodeHost host, CookieJar jar)
    {
        var response = await GetAsync(host.Client, "/identity/manage/authMethods", jar);
        await AssertStatusAsync(response, HttpStatusCode.OK);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        if (doc.RootElement.TryGetProperty("emailCode", out var camel))
        {
            return camel.GetBoolean();
        }

        return doc.RootElement.GetProperty("EmailCode").GetBoolean();
    }

    private static async Task<string> CsrfAsync(HttpClient client, CookieJar jar)
    {
        var response = await GetAsync(client, "/identity/csrfToken", jar);
        await AssertStatusAsync(response, HttpStatusCode.OK);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        if (doc.RootElement.TryGetProperty("csrfToken", out var camel))
        {
            return camel.GetString()!;
        }

        return doc.RootElement.GetProperty("CsrfToken").GetString()!;
    }

    private static async Task<HttpResponseMessage> SendReAuthAsync(EmailCodeHost host, CookieJar jar)
    {
        return await PostCsrfAsync(
            host.Client,
            "/identity/confirmIdentity/emailCode/send",
            new { },
            jar,
            await CsrfAsync(host.Client, jar));
    }

    private static async Task<HttpResponseMessage> ConfirmAsync(EmailCodeHost host, CookieJar jar, object body)
    {
        return await PostCsrfAsync(host.Client, "/identity/confirmIdentity", body, jar, await CsrfAsync(host.Client, jar));
    }

    private static async Task<HttpResponseMessage> PostCsrfAsync(
        HttpClient client,
        string url,
        object body,
        CookieJar jar,
        string csrf)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.TryAddWithoutValidation("RequestVerificationToken", csrf);
        jar.Apply(request, client.BaseAddress!);
        var response = await client.SendAsync(request);
        jar.Capture(response, client.BaseAddress!);
        return response;
    }

    private static async Task<HttpResponseMessage> PostHeadersAsync(
        HttpClient client,
        string url,
        object body,
        string cookieHeader,
        string csrf)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(body)
        };
        if (!string.IsNullOrEmpty(cookieHeader))
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
        }

        request.Headers.TryAddWithoutValidation("RequestVerificationToken", csrf);
        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> PostBearerAsync(HttpClient client, string url, object body, string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await client.SendAsync(request);
    }

    private static string CodeFor(CapturingEmailSender mail, string email, EmailCodePurpose purpose)
    {
        return mail.Snapshot().Last(item => item.Kind == "email-code" && item.Email == email && item.Purpose == purpose).Body;
    }

    private static CapturedMail MailForPurpose(CapturingEmailSender mail, string email, EmailCodePurpose purpose)
    {
        return mail.Snapshot().Single(item => item.Kind == "email-code" && item.Email == email && item.Purpose == purpose);
    }

    private static async Task<(int Expires, int Resend)> ReadSendAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var expires = doc.RootElement.TryGetProperty("expiresInSeconds", out var expiresValue)
            ? expiresValue.GetInt32()
            : doc.RootElement.GetProperty("ExpiresInSeconds").GetInt32();
        var resend = doc.RootElement.TryGetProperty("resendAfterSeconds", out var resendValue)
            ? resendValue.GetInt32()
            : doc.RootElement.GetProperty("ResendAfterSeconds").GetInt32();
        return (expires, resend);
    }

    private static async Task<string> ReadReauthTokenAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var token = TestHelpers.TryGetString(doc.RootElement, "reauthToken", "ReauthToken");
        Assert.False(string.IsNullOrWhiteSpace(token));
        Assert.False(doc.RootElement.TryGetProperty("accessToken", out _) || doc.RootElement.TryGetProperty("AccessToken", out _));
        return token!;
    }

    private static async Task AssertStatusAsync(HttpResponseMessage response, HttpStatusCode expected)
    {
        if (response.StatusCode == expected)
        {
            return;
        }

        Assert.Fail($"{(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
    }

    private static async Task UpdateStampAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await userManager.FindByEmailAsync(email);
        Assert.True((await userManager.UpdateSecurityStampAsync(user!)).Succeeded);
    }
}
