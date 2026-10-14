using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using AuthEndpoints.SignIn;
using AuthEndpoints.Tests.PublicApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Tests;

public class SignInCompleterTests
{
    [Fact]
    public async Task PasswordEmailCodeAndPasskey_MatchCookieBearerAndJwtShapes()
    {
        await using var host = await SignInHost.StartAsync(o => o.Map = SignInMaps.Sessions);

        foreach (var (prefix, kind) in new (string Prefix, SessionKind Kind)[]
        {
            ("/cookie", SessionKind.Cookie),
            ("/bearer", SessionKind.IdentityBearer),
            ("/jwt", SessionKind.Jwt),
        })
        {
            var email = UniqueEmail(prefix.Trim('/') + "-password");
            await host.SeedAsync(email);
            var login = await host.Client.PostAsync(prefix + "/login", new { email, password = TestHelpers.DefaultPassword });
            await AssertSession(login, kind, passkeyRegister: false);

            if (kind == SessionKind.IdentityBearer)
            {
                var cookieEmail = UniqueEmail("bearer-cookies");
                await host.SeedAsync(cookieEmail);
                var asCookie = await host.Client.PostAsync(
                    prefix + "/login?useCookies=true",
                    new { email = cookieEmail, password = TestHelpers.DefaultPassword });
                await AssertSession(asCookie, SessionKind.Cookie, passkeyRegister: false);
            }

            var codeEmail = UniqueEmail(prefix.Trim('/') + "-code");
            await host.SeedAsync(codeEmail);
            Assert.Equal(HttpStatusCode.OK, (await host.Client.PostAsync(prefix + "/emailCode/send", new { email = codeEmail })).StatusCode);
            var verify = await host.Client.PostAsync(
                prefix + "/emailCode/verify",
                new { email = codeEmail, code = host.Code(codeEmail) });
            await AssertSession(verify, kind, passkeyRegister: false);

            var passkeyEmail = UniqueEmail(prefix.Trim('/') + "-passkey");
            var (register, credentialId) = await host.RegisterPasskeyAsync(prefix + "/passkeys", passkeyEmail);
            await AssertSession(register, kind, passkeyRegister: true);

            var loginOptions = await host.Client.PostAsync(
                prefix + "/passkeys/requestOptions",
                new { email = passkeyEmail },
                csrf: true);
            Assert.Equal(HttpStatusCode.OK, loginOptions.StatusCode);
            var assertion = host.Authenticator.CreateAssertion(
                await loginOptions.Content.ReadAsStringAsync(),
                host.Client.Origin,
                credentialId);
            var passkeyLogin = await host.Client.PostAsync(
                prefix + "/passkeys/login",
                new { credentialJson = assertion },
                csrf: true);
            await AssertSession(passkeyLogin, kind, passkeyRegister: false);
        }
    }

    [Fact]
    public async Task NoArgument_StaysOn3xHandlers_AndDoesNotResolveKeyedCompleter()
    {
        await using var host = await SignInHost.StartAsync(o =>
        {
            o.SpyOnBuiltInNames = true;
            o.Map = SignInMaps.Defaults;
        });

        using (var app = MapForMetadata(services =>
        {
            AddIdentityStack(services);
            services.AddSingleton(host.Counter);
            services.AddSignInCompleter<TestAppUser, CountingSignInCompleter>(SignInCompleters.Cookie);
            services.AddSignInCompleter<TestAppUser, CountingSignInCompleter>(SignInCompleters.IdentityBearer);
            services.AddSignInCompleter<TestAppUser, CountingSignInCompleter>(SignInCompleters.Jwt);
        }, SignInMaps.Defaults))
        {
            Assert.Equal("LoginCookie", HandlerName(Find(app, "POST /default-cookie/login")));
            Assert.Equal("Login", HandlerName(Find(app, "POST /default-bearer/login")));
            Assert.Null(Find(app, "POST /default-cookie/login").Metadata.GetMetadata<SignInCompleterSelection>());
            Assert.NotNull(Find(app, "POST /default-email/emailCode/verify").Metadata.GetMetadata<HonorSignInCompletionDefault>());
            Assert.Null(Find(app, "POST /default-passkey/passkeys/login").Metadata.GetMetadata<SignInCompleterSelection>());
        }

        var cookieEmail = UniqueEmail("default-cookie");
        await host.SeedAsync(cookieEmail);
        var cookie = await host.Client.PostAsync("/default-cookie/login", new { email = cookieEmail, password = TestHelpers.DefaultPassword });
        await AssertSession(cookie, SessionKind.Cookie, passkeyRegister: false);

        var bearerEmail = UniqueEmail("default-bearer");
        await host.SeedAsync(bearerEmail);
        var bearer = await host.Client.PostAsync("/default-bearer/login", new { email = bearerEmail, password = TestHelpers.DefaultPassword });
        await AssertSession(bearer, SessionKind.IdentityBearer, passkeyRegister: false);

        var codeEmail = UniqueEmail("default-code");
        await host.SeedAsync(codeEmail);
        Assert.Equal(HttpStatusCode.OK, (await host.Client.PostAsync("/default-email/emailCode/send", new { email = codeEmail })).StatusCode);
        var verify = await host.Client.PostAsync(
            "/default-email/emailCode/verify",
            new { email = codeEmail, code = host.Code(codeEmail) });
        await AssertSession(verify, SessionKind.IdentityBearer, passkeyRegister: false);

        var passkeyEmail = UniqueEmail("default-passkey");
        var (register, _) = await host.RegisterPasskeyAsync("/default-passkey/passkeys", passkeyEmail);
        await AssertSession(register, SessionKind.IdentityBearer, passkeyRegister: true);

        Assert.Equal(0, host.Counter.Calls);
        Assert.Equal(0, host.Counter.Constructions);
    }

    [Fact]
    public async Task DefaultOption_SelectsKeyedCompleter_CompositesStayOn3xHandlers()
    {
        await using var host = await SignInHost.StartAsync(o =>
        {
            o.DefaultCompleter = SignInCompleters.Jwt;
            o.Map = app =>
            {
                app.MapGroup("/password").MapPasswordEndpoints<TestAppUser>();
                app.MapGroup("/none").MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.None, "default-none-confirm");
                app.MapGroup("/cookie").MapCookieAuthEndpoints<TestAppUser>();
                app.MapGroup("/bearer").MapBearerAuthEndpoints<TestAppUser>();
                app.MapGroup("/email").MapEmailCodeEndpoints<TestAppUser>();
                app.MapGroup("/passkey").MapPasskeySignInEndpoints<TestAppUser>("default-passkey-confirm");
                app.MapGroup("/account").MapPasskeyEndpoints<TestAppUser>("default-account-confirm");
            };
        });

        Assert.Equal(SignInCompleters.Jwt, Find(host.App, "POST /password/login").Metadata.GetMetadata<SignInCompleterSelection>()?.Name);
        Assert.Equal("LoginCookie", HandlerName(Find(host.App, "POST /cookie/login")));
        Assert.Equal("Login", HandlerName(Find(host.App, "POST /bearer/login")));
        Assert.Null(Find(host.App, "POST /cookie/login").Metadata.GetMetadata<HonorSignInCompletionDefault>());
        Assert.Null(Find(host.App, "POST /account/passkeys/login").Metadata.GetMetadata<HonorSignInCompletionDefault>());
        Assert.Null(Find(host.App, "POST /account/passkeys/login").Metadata.GetMetadata<SignInCompleterSelection>());
        Assert.Null(TryFind(host.App, "POST /none/login"));

        var email = UniqueEmail("default-jwt");
        await host.SeedAsync(email);
        var password = await host.Client.PostAsync("/password/login", new { email, password = TestHelpers.DefaultPassword });
        await AssertSession(password, SessionKind.Jwt, passkeyRegister: false);

        var cookieEmail = UniqueEmail("composite-cookie");
        await host.SeedAsync(cookieEmail);
        var cookie = await host.Client.PostAsync("/cookie/login", new { email = cookieEmail, password = TestHelpers.DefaultPassword });
        await AssertSession(cookie, SessionKind.Cookie, passkeyRegister: false);

        var bearerEmail = UniqueEmail("composite-bearer");
        await host.SeedAsync(bearerEmail);
        var bearer = await host.Client.PostAsync("/bearer/login", new { email = bearerEmail, password = TestHelpers.DefaultPassword });
        await AssertSession(bearer, SessionKind.IdentityBearer, passkeyRegister: false);

        var codeEmail = UniqueEmail("default-email-jwt");
        await host.SeedAsync(codeEmail);
        Assert.Equal(HttpStatusCode.OK, (await host.Client.PostAsync("/email/emailCode/send", new { email = codeEmail })).StatusCode);
        var verify = await host.Client.PostAsync("/email/emailCode/verify", new { email = codeEmail, code = host.Code(codeEmail) });
        await AssertSession(verify, SessionKind.Jwt, passkeyRegister: false);
    }

    [Fact]
    public async Task Spy_IsNotCalledOnFailure_AndIsCalledAfterAcceptedProof()
    {
        await using var host = await SignInHost.StartAsync(o =>
        {
            o.RegisterKeyedSpy = true;
            o.SpyName = "Spy";
            o.Map = app => SignInMaps.Named(app, "Spy");
        });

        Assert.Equal(0, host.Counter.Constructions);

        var unknown = await host.Client.PostAsync("/password/login", new { email = UniqueEmail("missing"), password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        await host.Client.PostAsync("/password/login", new { email = "", password = TestHelpers.DefaultPassword });

        var badEmail = UniqueEmail("bad-password");
        await host.SeedAsync(badEmail);
        var bad = await host.Client.PostAsync("/password/login", new { email = badEmail, password = "wrong-password" });
        Assert.Equal("Unauthorized", await TitleAsync(bad));

        var lockedEmail = UniqueEmail("locked");
        await host.SeedAsync(lockedEmail, locked: true);
        var locked = await host.Client.PostAsync("/password/login", new { email = lockedEmail, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, locked.StatusCode);

        var factorEmail = UniqueEmail("factor");
        await host.SeedAsync(factorEmail, twoFactor: true);
        var missingFactor = await host.Client.PostAsync("/password/login", new { email = factorEmail, password = TestHelpers.DefaultPassword });
        Assert.Equal("RequiresTwoFactor", await TitleAsync(missingFactor));
        var wrongFactor = await host.Client.PostAsync(
            "/password/login",
            new { email = factorEmail, password = TestHelpers.DefaultPassword, twoFactorCode = WrongTotp(await host.AuthenticatorKeyAsync(factorEmail)) });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongFactor.StatusCode);
        var wrongRecovery = await host.Client.PostAsync(
            "/password/login",
            new { email = factorEmail, password = TestHelpers.DefaultPassword, twoFactorRecoveryCode = "not-a-recovery-code" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongRecovery.StatusCode);

        var codeEmail = UniqueEmail("bad-code");
        await host.SeedAsync(codeEmail);
        Assert.Equal(HttpStatusCode.OK, (await host.Client.PostAsync("/password/emailCode/send", new { email = codeEmail })).StatusCode);
        var wrongCode = await host.Client.PostAsync("/password/emailCode/verify", new { email = codeEmail, code = "000000" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongCode.StatusCode);

        var lockedCode = UniqueEmail("locked-code");
        await host.SeedAsync(lockedCode);
        Assert.Equal(HttpStatusCode.OK, (await host.Client.PostAsync("/password/emailCode/send", new { email = lockedCode })).StatusCode);
        await host.LockAsync(lockedCode);
        var lockedVerify = await host.Client.PostAsync("/password/emailCode/verify", new { email = lockedCode, code = host.Code(lockedCode) });
        Assert.Equal(HttpStatusCode.Unauthorized, lockedVerify.StatusCode);

        var factorCode = UniqueEmail("factor-code");
        await host.SeedAsync(factorCode, twoFactor: true);
        Assert.Equal(HttpStatusCode.OK, (await host.Client.PostAsync("/password/emailCode/send", new { email = factorCode })).StatusCode);
        var missingCodeFactor = await host.Client.PostAsync("/password/emailCode/verify", new { email = factorCode, code = host.Code(factorCode) });
        Assert.Equal("RequiresTwoFactor", await TitleAsync(missingCodeFactor));
        var wrongCodeFactor = await host.Client.PostAsync(
            "/password/emailCode/verify",
            new { email = factorCode, code = host.Code(factorCode), twoFactorCode = WrongTotp(await host.AuthenticatorKeyAsync(factorCode)) });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongCodeFactor.StatusCode);

        var badPasskey = await host.Client.PostAsync("/password/passkeys/login", new { credentialJson = "" }, csrf: true);
        Assert.Equal(HttpStatusCode.BadRequest, badPasskey.StatusCode);

        Assert.Equal(0, host.Counter.Calls);
        Assert.Equal(0, host.Counter.Constructions);

        var ok = await host.Client.PostAsync("/password/login", new { email = badEmail, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(1, host.Counter.Calls);
        Assert.Equal(1, host.Counter.Constructions);

        var codeOkEmail = UniqueEmail("code-ok");
        await host.SeedAsync(codeOkEmail);
        Assert.Equal(HttpStatusCode.OK, (await host.Client.PostAsync("/password/emailCode/send", new { email = codeOkEmail })).StatusCode);
        var codeOk = await host.Client.PostAsync("/password/emailCode/verify", new { email = codeOkEmail, code = host.Code(codeOkEmail) });
        Assert.Equal(HttpStatusCode.OK, codeOk.StatusCode);
        Assert.Equal(2, host.Counter.Calls);

        var passkeyEmail = UniqueEmail("passkey-ok");
        var (registered, credentialId) = await host.RegisterPasskeyAsync("/password/passkeys", passkeyEmail);
        Assert.Equal(HttpStatusCode.OK, registered.StatusCode);
        Assert.Equal(3, host.Counter.Calls);

        await host.LockAsync(passkeyEmail);
        var options = await host.Client.PostAsync("/password/passkeys/requestOptions", new { email = passkeyEmail }, csrf: true);
        var assertion = host.Authenticator.CreateAssertion(
            await options.Content.ReadAsStringAsync(),
            host.Client.Origin,
            credentialId);
        var lockedPasskey = await host.Client.PostAsync("/password/passkeys/login", new { credentialJson = assertion }, csrf: true);
        Assert.Equal(HttpStatusCode.Unauthorized, lockedPasskey.StatusCode);
        Assert.Equal(3, host.Counter.Calls);
        Assert.Equal(3, host.Counter.Constructions);
    }

    [Fact]
    public async Task NotAllowed_DoesNotCallSpy()
    {
        await using var passwordHost = await SignInHost.StartAsync(o =>
        {
            o.RequireConfirmedAccount = true;
            o.RegisterKeyedSpy = true;
            o.SpyName = "Spy";
            o.Map = app => app.MapGroup("/password").MapPasswordEndpoints<TestAppUser>("Spy", "unconfirmed-confirm");
        });
        var unconfirmed = UniqueEmail("unconfirmed");
        await passwordHost.SeedAsync(unconfirmed, confirmed: false);
        var denied = await passwordHost.Client.PostAsync("/password/login", new { email = unconfirmed, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.Equal(0, passwordHost.Counter.Calls);
        Assert.Equal(0, passwordHost.Counter.Constructions);

        await using var emailHost = await SignInHost.StartAsync(o =>
        {
            o.RequireConfirmedPhoneNumber = true;
            o.RegisterKeyedSpy = true;
            o.SpyName = "Spy";
            o.Map = app => app.MapGroup("/email").MapEmailCodeEndpoints<TestAppUser>("Spy");
        });
        var phone = UniqueEmail("phone");
        await emailHost.SeedAsync(phone);
        Assert.Equal(HttpStatusCode.OK, (await emailHost.Client.PostAsync("/email/emailCode/send", new { email = phone })).StatusCode);
        var emailDenied = await emailHost.Client.PostAsync("/email/emailCode/verify", new { email = phone, code = emailHost.Code(phone) });
        Assert.Equal(HttpStatusCode.Unauthorized, emailDenied.StatusCode);
        Assert.Equal(0, emailHost.Counter.Calls);
        Assert.Equal(0, emailHost.Counter.Constructions);

        await using var passkeyHost = await SignInHost.StartAsync(o =>
        {
            o.RequireConfirmedAccount = true;
            o.RegisterKeyedSpy = true;
            o.SpyName = "Spy";
            o.Map = app => app.MapGroup("/passkey").MapPasskeySignInEndpoints<TestAppUser>("Spy", "unconfirmed-passkey-confirm");
        });
        var (register, _) = await passkeyHost.RegisterPasskeyAsync("/passkey/passkeys", UniqueEmail("unconfirmed-passkey"));
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);
        using var doc = JsonDocument.Parse(await register.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrEmpty(TestHelpers.TryGetString(doc.RootElement, "credentialId", "CredentialId")));
        Assert.Equal(0, passkeyHost.Counter.Calls);
        Assert.Equal(0, passkeyHost.Counter.Constructions);
    }

    [Fact]
    public async Task LegacyCompleter_WinsOverDefault_ExplicitMapWinsOverLegacy()
    {
        await using var host = await SignInHost.StartAsync(o =>
        {
            o.DefaultCompleter = SignInCompleters.Jwt;
            o.RegisterKeyedSpy = true;
            o.SpyName = SignInCompleters.Jwt;
            o.LegacyEmail = true;
            o.LegacyPasskey = true;
            o.Map = app =>
            {
                app.MapGroup("/email").MapEmailCodeEndpoints<TestAppUser>();
                app.MapGroup("/email-jwt").MapEmailCodeEndpoints<TestAppUser>(AuthEndpointsSession.Jwt);
                app.MapGroup("/passkey").MapPasskeySignInEndpoints<TestAppUser>("legacy-passkey-confirm");
                app.MapGroup("/passkey-jwt").MapPasskeySignInEndpoints<TestAppUser>(AuthEndpointsSession.Jwt, "legacy-passkey-jwt-confirm");
            };
        });

        var email = UniqueEmail("legacy-email");
        await host.SeedAsync(email);
        Assert.Equal(HttpStatusCode.OK, (await host.Client.PostAsync("/email/emailCode/send", new { email })).StatusCode);
        var legacy = await host.Client.PostAsync("/email/emailCode/verify", new { email, code = host.Code(email) });
        Assert.Equal("email", await MarkerAsync(legacy));
        Assert.Equal(1, host.LegacyEmailCount.Calls);
        Assert.Equal(0, host.Counter.Calls);

        var forcedEmail = UniqueEmail("forced-email");
        await host.SeedAsync(forcedEmail);
        Assert.Equal(HttpStatusCode.OK, (await host.Client.PostAsync("/email-jwt/emailCode/send", new { email = forcedEmail })).StatusCode);
        var forced = await host.Client.PostAsync("/email-jwt/emailCode/verify", new { email = forcedEmail, code = host.Code(forcedEmail) });
        Assert.Equal("keyed", await MarkerAsync(forced));
        Assert.Equal(1, host.LegacyEmailCount.Calls);
        Assert.Equal(1, host.Counter.Calls);

        var (passkey, _) = await host.RegisterPasskeyAsync("/passkey/passkeys", UniqueEmail("legacy-passkey"));
        Assert.Equal("passkey", await MarkerAsync(passkey));
        Assert.Equal(1, host.LegacyPasskeyCount.Calls);
        Assert.Equal(1, host.Counter.Calls);

        var (forcedPasskey, _) = await host.RegisterPasskeyAsync("/passkey-jwt/passkeys", UniqueEmail("forced-passkey"));
        Assert.Equal("keyed", await MarkerAsync(forcedPasskey));
        Assert.Equal(1, host.LegacyPasskeyCount.Calls);
        Assert.Equal(2, host.Counter.Calls);
    }

    [Fact]
    public void UnknownCompleterName_ThrowsAddSignInCompleterMessage()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => MapForMetadata(
            services => services.AddPasswordEndpoints(),
            app => app.MapPasswordEndpoints<TestAppUser>("missing")));

        Assert.Equal(
            "No ISignInCompleter<TestAppUser> named 'missing' is registered (AddSignInCompleter).",
            ex.Message);
    }

    [Fact]
    public void JwtWithoutAddJwtEndpoints_ThrowsNamedFix()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => MapForMetadata(
            services => services.AddPasswordEndpoints(),
            app => app.MapPasswordEndpoints<TestAppUser>(AuthEndpointsSession.Jwt)));

        Assert.Contains("Call AddJwtEndpoints before", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddSignInCompleter_LastClosedRegistrationWinsOverOpenGeneric()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase("completer-wins-" + Guid.NewGuid().ToString("N")));
        services.AddIdentityApiEndpoints<TestAppUser>(o => o.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
            .AddEntityFrameworkStores<TestDbContext>();
        services.AddSignInCompleter<TestAppUser, AlphaCompleter>(SignInCompleters.Cookie);
        services.AddPasswordEndpoints();
        services.AddSignInCompleter<TestAppUser, AlphaCompleter>("custom");
        services.AddSignInCompleter<TestAppUser, BetaCompleter>("custom");

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        Assert.IsType<AlphaCompleter>(scope.ServiceProvider.GetRequiredKeyedService<ISignInCompleter<TestAppUser>>(SignInCompleters.Cookie));
        Assert.IsType<BetaCompleter>(scope.ServiceProvider.GetRequiredKeyedService<ISignInCompleter<TestAppUser>>("custom"));
    }

    [Fact]
    public void PerMethodCompleters_AreObsolete_PasskeySignInKindIsNot()
    {
        AssertObsolete(typeof(IEmailCodeSignInCompleter<>));
        AssertObsolete(typeof(EmailCodeSignInContext));
        AssertObsolete(typeof(IdentityEmailCodeSignInCompleter<>));
        AssertObsolete(typeof(JwtEmailCodeSignInCompleter<>));
        AssertObsolete(typeof(IPasskeySignInCompleter<>));
        AssertObsolete(typeof(PasskeySignInCompletionContext));
        AssertObsolete(typeof(IdentityPasskeySignInCompleter<>));
        AssertObsolete(typeof(JwtPasskeySignInCompleter<>));
        AssertObsolete(typeof(AuthEndpoints.EmailCode.ServiceCollectionExtensions).GetMethod("AddEmailCodeSignInCompleter")!);
        AssertObsolete(typeof(AuthEndpoints.Passkey.ServiceCollectionExtensions).GetMethod("AddPasskeySignInCompleter")!);
        Assert.Null(typeof(PasskeySignInKind).GetCustomAttribute<ObsoleteAttribute>());
    }

    [Fact]
    public void PasskeyStringOverload_KeepsSingleStringAsConfirmEmailName()
    {
        using var app = MapForMetadata(services =>
        {
            services.AddIdentityApiEndpoints<TestAppUser>(o => o.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
                .AddEntityFrameworkStores<TestDbContext>();
            services.AddPasskeyEndpoints<TestAppUser>();
            services.Configure<IdentityPasskeyOptions>(o => o.ServerDomain = "localhost");
            services.AddSignInCompleter<TestAppUser, AlphaCompleter>("MySession");
        }, app =>
        {
            app.MapPasskeySignInEndpoints<TestAppUser>("confirm-only");
            app.MapGroup("/named").MapPasskeySignInEndpoints<TestAppUser>("MySession", confirmEmailEndpointName: null);
        });

        Assert.Equal("confirm-only", Find(app, "GET /confirmEmail").Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName);
        Assert.Null(Find(app, "POST /passkeys/login").Metadata.GetMetadata<SignInCompleterSelection>());
        Assert.NotNull(Find(app, "POST /passkeys/login").Metadata.GetMetadata<HonorSignInCompletionDefault>());
        Assert.Equal("MySession", Find(app, "POST /named/passkeys/login").Metadata.GetMetadata<SignInCompleterSelection>()?.Name);
        Assert.Equal("MySession", Find(app, "POST /named/passkeys/register").Metadata.GetMetadata<SignInCompleterSelection>()?.Name);
    }

    [Fact]
    public void PasskeyStringOverload_WarnsWhenStringMatchesRegisteredCompleter()
    {
        var logs = new WarningLoggerProvider();
        using var app = MapForMetadata(services =>
        {
            services.AddIdentityApiEndpoints<TestAppUser>(o => o.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
                .AddEntityFrameworkStores<TestDbContext>();
            services.AddPasskeyEndpoints<TestAppUser>();
            services.Configure<IdentityPasskeyOptions>(o => o.ServerDomain = "localhost");
            services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            });
            services.AddSignInCompleter<TestAppUser, AlphaCompleter>("MySession");
            services.AddSingleton<ILoggerProvider>(logs);
        }, app =>
        {
            app.MapGroup("/mine").MapPasskeySignInEndpoints<TestAppUser>("MySession");
            app.MapGroup("/jwt").MapPasskeySignInEndpoints<TestAppUser>(SignInCompleters.Jwt);
            app.MapGroup("/plain").MapPasskeySignInEndpoints<TestAppUser>("confirm-only");
        });

        AssertConfirmNameStillDefault(app, "/mine", "MySession");
        AssertConfirmNameStillDefault(app, "/jwt", SignInCompleters.Jwt);
        AssertConfirmNameStillDefault(app, "/plain", "confirm-only");
        Assert.Contains(logs.Messages, message => message.Contains("MySession", StringComparison.Ordinal)
            && message.Contains("confirm-email", StringComparison.Ordinal)
            && message.Contains("AuthEndpointsSession", StringComparison.Ordinal));
        Assert.Contains(logs.Messages, message => message.Contains("'Jwt'", StringComparison.Ordinal)
            && message.Contains("AuthEndpointsSession", StringComparison.Ordinal));
        Assert.DoesNotContain(logs.Messages, message => message.Contains("confirm-only", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ExplicitPasswordLoginMode_BeatsSignInCompletionDefault()
    {
        await using var host = await SignInHost.StartAsync(o =>
        {
            o.DefaultCompleter = SignInCompleters.Jwt;
            o.Map = app =>
            {
                app.MapGroup("/open").MapPasswordEndpoints<TestAppUser>();
                app.MapGroup("/cookie").MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.Cookie, "mode-cookie-confirm");
                app.MapGroup("/bearer").MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.IdentityBearer, "mode-bearer-confirm");
            };
        });

        Assert.Equal(SignInCompleters.Jwt, Find(host.App, "POST /open/login").Metadata.GetMetadata<SignInCompleterSelection>()?.Name);
        Assert.Equal("LoginCookie", HandlerName(Find(host.App, "POST /cookie/login")));
        Assert.Null(Find(host.App, "POST /cookie/login").Metadata.GetMetadata<SignInCompleterSelection>());
        Assert.Null(Find(host.App, "POST /cookie/login").Metadata.GetMetadata<HonorSignInCompletionDefault>());
        Assert.Equal("Login", HandlerName(Find(host.App, "POST /bearer/login")));
        Assert.Null(Find(host.App, "POST /bearer/login").Metadata.GetMetadata<SignInCompleterSelection>());
        Assert.Null(Find(host.App, "POST /bearer/login").Metadata.GetMetadata<HonorSignInCompletionDefault>());

        var open = UniqueEmail("open-default");
        await host.SeedAsync(open);
        await AssertSession(
            await host.Client.PostAsync("/open/login", new { email = open, password = TestHelpers.DefaultPassword }),
            SessionKind.Jwt,
            passkeyRegister: false);

        var cookie = UniqueEmail("mode-cookie");
        await host.SeedAsync(cookie);
        await AssertSession(
            await host.Client.PostAsync("/cookie/login", new { email = cookie, password = TestHelpers.DefaultPassword }),
            SessionKind.Cookie,
            passkeyRegister: false);

        var bearer = UniqueEmail("mode-bearer");
        await host.SeedAsync(bearer);
        await AssertSession(
            await host.Client.PostAsync("/bearer/login", new { email = bearer, password = TestHelpers.DefaultPassword }),
            SessionKind.IdentityBearer,
            passkeyRegister: false);
    }

    [Fact]
    public async Task Facade_IgnoresSignInCompletionDefault()
    {
        var mail = new CapturingEmailSender();
        WebApplication? cookieApp = null;
        WebApplication? bearerApp = null;
        try
        {
            cookieApp = await StartFacadeAsync(AuthEndpointsSignIn.Cookie, mail);
            using var cookieClient = new ApiClient(cookieApp);

            Assert.Equal("LoginCookie", HandlerName(Find(cookieApp, "POST /identity/login")));
            Assert.Null(Find(cookieApp, "POST /identity/login").Metadata.GetMetadata<SignInCompleterSelection>());
            Assert.Null(Find(cookieApp, "POST /identity/login").Metadata.GetMetadata<HonorSignInCompletionDefault>());
            var verify = Find(cookieApp, "POST /identity/emailCode/verify");
            Assert.Null(verify.Metadata.GetMetadata<HonorSignInCompletionDefault>());
            Assert.Null(verify.Metadata.GetMetadata<SignInCompleterSelection>());
            var passkey = Find(cookieApp, "POST /account/passkeys/login");
            Assert.Null(passkey.Metadata.GetMetadata<HonorSignInCompletionDefault>());
            Assert.Null(passkey.Metadata.GetMetadata<SignInCompleterSelection>());

            var cookieEmail = UniqueEmail("facade-cookie");
            Assert.Equal(HttpStatusCode.OK, (await cookieClient.PostAsync("/identity/register", new { email = cookieEmail, password = TestHelpers.DefaultPassword })).StatusCode);
            await AssertSession(
                await cookieClient.PostAsync("/identity/login", new { email = cookieEmail, password = TestHelpers.DefaultPassword }),
                SessionKind.Cookie,
                passkeyRegister: false);

            Assert.Equal(HttpStatusCode.OK, (await cookieClient.PostAsync("/identity/emailCode/send", new { email = cookieEmail })).StatusCode);
            await AssertSession(
                await cookieClient.PostAsync("/identity/emailCode/verify", new { email = cookieEmail, code = CodeFor(mail, cookieEmail) }),
                SessionKind.IdentityBearer,
                passkeyRegister: false);

            bearerApp = await StartFacadeAsync(AuthEndpointsSignIn.IdentityBearer, new CapturingEmailSender());
            using var bearerClient = new ApiClient(bearerApp);
            Assert.Equal("Login", HandlerName(Find(bearerApp, "POST /identity/login")));
            Assert.Null(Find(bearerApp, "POST /identity/login").Metadata.GetMetadata<SignInCompleterSelection>());
            Assert.Null(Find(bearerApp, "POST /identity/login").Metadata.GetMetadata<HonorSignInCompletionDefault>());
            Assert.Null(Find(bearerApp, "POST /identity/emailCode/verify").Metadata.GetMetadata<HonorSignInCompletionDefault>());
            var bearerEmail = UniqueEmail("facade-bearer");
            Assert.Equal(HttpStatusCode.OK, (await bearerClient.PostAsync("/identity/register", new { email = bearerEmail, password = TestHelpers.DefaultPassword })).StatusCode);
            await AssertSession(
                await bearerClient.PostAsync("/identity/login", new { email = bearerEmail, password = TestHelpers.DefaultPassword }),
                SessionKind.IdentityBearer,
                passkeyRegister: false);
        }
        finally
        {
            await DisposeFacadeAsync(cookieApp);
            await DisposeFacadeAsync(bearerApp);
        }
    }

    [Fact]
    public void CompleterName_IsCheckedPerUserType()
    {
        OtherUserCompleter.Constructions = 0;
        var missing = Assert.Throws<InvalidOperationException>(() => MapForMetadata(
            services =>
            {
                services.AddPasswordEndpoints();
                services.AddSignInCompleter<OtherSignInUser, OtherUserCompleter>("MySession");
            },
            app => app.MapPasswordEndpoints<TestAppUser>("MySession")));
        Assert.Equal(
            "No ISignInCompleter<TestAppUser> named 'MySession' is registered (AddSignInCompleter).",
            missing.Message);
        Assert.Equal(0, OtherUserCompleter.Constructions);

        using var sameUser = MapForMetadata(services =>
        {
            services.AddPasswordEndpoints();
            services.AddSignInCompleter<OtherSignInUser, OtherUserCompleter>("MySession");
            services.AddSignInCompleter<TestAppUser, AlphaCompleter>("MySession");
        }, app => app.MapPasswordEndpoints<TestAppUser>("MySession"));
        Assert.Equal("MySession", Find(sameUser, "POST /login").Metadata.GetMetadata<SignInCompleterSelection>()?.Name);
        Assert.Equal(0, OtherUserCompleter.Constructions);

        using var openGeneric = MapForMetadata(
            services => services.AddPasswordEndpoints(),
            app => app.MapPasswordEndpoints<TestAppUser>(SignInCompleters.Cookie));
        Assert.Equal(SignInCompleters.Cookie, Find(openGeneric, "POST /login").Metadata.GetMetadata<SignInCompleterSelection>()?.Name);

        var wrongDefault = Assert.Throws<InvalidOperationException>(() => MapForMetadata(services =>
        {
            services.AddIdentityApiEndpoints<TestAppUser>(o => o.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
                .AddEntityFrameworkStores<TestDbContext>();
            services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>(_ => { });
            services.AddSignInCompleter<OtherSignInUser, OtherUserCompleter>("MySession");
            services.Configure<SignInCompletionOptions>(o => o.Default = "MySession");
        }, app => app.MapEmailCodeEndpoints<TestAppUser>()));
        Assert.Equal(
            "No ISignInCompleter<TestAppUser> named 'MySession' is registered (AddSignInCompleter).",
            wrongDefault.Message);
        Assert.Equal(0, OtherUserCompleter.Constructions);
    }

    [Fact]
    public void ParameterlessPasswordMaps_UseCookiePipeline()
    {
        using var app = MapForMetadata(services =>
        {
            services.AddIdentityApiEndpoints<TestAppUser>(o => o.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
                .AddEntityFrameworkStores<TestDbContext>();
            services.AddPasswordEndpoints();
            services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            });
        }, app =>
        {
            app.MapPasswordEndpoints<TestAppUser>();
            app.MapGroup("/in").MapPasswordSignInEndpoints<TestAppUser>();
            app.MapGroup("/auth").MapJwtPasswordEndpoints<TestAppUser>();
            app.MapGroup("/mode").MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.Cookie, "mode-confirm");
        });

        Assert.Equal(SignInCompleters.Cookie, Find(app, "POST /login").Metadata.GetMetadata<SignInCompleterSelection>()?.Name);
        Assert.Equal(SignInCompleters.Cookie, Find(app, "POST /in/login").Metadata.GetMetadata<SignInCompleterSelection>()?.Name);
        Assert.NotEqual("LoginCookie", HandlerName(Find(app, "POST /login")));
        Assert.Equal(SignInCompleters.Jwt, Find(app, "POST /auth/create").Metadata.GetMetadata<SignInCompleterSelection>()?.Name);
        Assert.Equal("HandleCreate", HandlerName(Find(app, "POST /auth/create")));
        Assert.Equal("LoginCookie", HandlerName(Find(app, "POST /mode/login")));
        Assert.Null(Find(app, "POST /mode/login").Metadata.GetMetadata<SignInCompleterSelection>());
    }

    [Fact]
    public async Task Facade_JwtCreate_Keeps341FailureBodies_AndDoesNotCountTwoFactorFailures()
    {
        var app = await StartFacadeAsync(AuthEndpointsSignIn.Cookie, new CapturingEmailSender());
        try
        {
            Assert.Equal("Create", HandlerName(Find(app, "POST /auth/create")));
            Assert.Null(Find(app, "POST /auth/create").Metadata.GetMetadata<SignInCompleterSelection>());
            Assert.Equal("LoginCookie", HandlerName(Find(app, "POST /identity/login")));

            var email = UniqueEmail("facade-create");
            string key;
            using (var scope = app.Services.CreateScope())
            {
                var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
                var user = new TestAppUser
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true,
                };
                Assert.True((await users.CreateAsync(user, TestHelpers.DefaultPassword)).Succeeded);
                Assert.True((await users.ResetAuthenticatorKeyAsync(user)).Succeeded);
                Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
                key = (await users.GetAuthenticatorKeyAsync(user))!;
            }

            using var client = new ApiClient(app);
            var wrongCode = await client.PostAsync(
                "/auth/create",
                new { email, password = TestHelpers.DefaultPassword, twoFactorCode = WrongTotp(key) });
            Assert.Equal(HttpStatusCode.Unauthorized, wrongCode.StatusCode);
            Assert.Contains("Invalid two factor code", await wrongCode.Content.ReadAsStringAsync(), StringComparison.Ordinal);
            Assert.Equal(0, await FailedCountAsync(app, email));

            var wrongRecovery = await client.PostAsync(
                "/auth/create",
                new { email, password = TestHelpers.DefaultPassword, twoFactorRecoveryCode = "not-a-recovery-code" });
            Assert.Equal(HttpStatusCode.Unauthorized, wrongRecovery.StatusCode);
            Assert.Contains(
                "Recovery code redemption failed",
                await wrongRecovery.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
            Assert.Equal(0, await FailedCountAsync(app, email));
        }
        finally
        {
            await DisposeFacadeAsync(app);
        }
    }

    private static async Task<int> FailedCountAsync(WebApplication app, string email)
    {
        using var scope = app.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await users.FindByEmailAsync(email);
        Assert.NotNull(user);
        return await users.GetAccessFailedCountAsync(user);
    }

    private static void AssertConfirmNameStillDefault(WebApplication app, string prefix, string confirmName)
    {
        Assert.Equal(confirmName, Find(app, "GET " + prefix + "/confirmEmail").Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName);
        var login = Find(app, "POST " + prefix + "/passkeys/login");
        Assert.Null(login.Metadata.GetMetadata<SignInCompleterSelection>());
        Assert.NotNull(login.Metadata.GetMetadata<HonorSignInCompletionDefault>());
        var register = Find(app, "POST " + prefix + "/passkeys/register");
        Assert.Null(register.Metadata.GetMetadata<SignInCompleterSelection>());
        Assert.NotNull(register.Metadata.GetMetadata<HonorSignInCompletionDefault>());
    }

    private static async Task<WebApplication> StartFacadeAsync(AuthEndpointsSignIn signIn, CapturingEmailSender mail)
    {
        var path = Path.Combine(Path.GetTempPath(), $"ae-facade-{Guid.NewGuid():N}.sqlite");
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(db => db.UseSqlite($"Data Source={path}"));
        builder.Services.AddSingleton(new FacadeDatabase(path));
        builder.Services.AddSingleton<IEmailSender<TestAppUser>>(mail);
        builder.Services.AddSingleton<IEmailCodeSender<TestAppUser>>(mail);
        builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(signIn, options =>
        {
            options.Passkeys.ServerDomain = "localhost";
            options.RequireConfirmedAccount = false;
            options.RequireEmailSenderInProduction = false;
            options.ConfigureIdentity = identity =>
            {
                identity.SignIn.RequireConfirmedAccount = false;
            };
            options.EmailCode.Enabled = true;
            options.Jwt.Enabled = true;
            options.Jwt.Configure = jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            };
        });
        builder.Services.Configure<SignInCompletionOptions>(completion => completion.Default = SignInCompleters.Jwt);

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

    private sealed class FacadeDatabase(string path)
    {
        public string Path { get; } = path;
    }

    private static async Task DisposeFacadeAsync(WebApplication? app)
    {
        if (app is null)
        {
            return;
        }

        var path = app.Services.GetRequiredService<FacadeDatabase>().Path;
        await app.DisposeAsync();
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try
            {
                var file = path + suffix;
                if (File.Exists(file))
                {
                    File.Delete(file);
                }
            }
            catch (IOException)
            {
            }
        }
    }

    private static string CodeFor(CapturingEmailSender mail, string email)
    {
        return mail.Snapshot().Last(item => item.Kind == "email-code" && item.Email == email).Body;
    }

    private static WebApplication MapForMetadata(Action<IServiceCollection> configure, Action<WebApplication> map)
    {
        return RouteSurface.Build(builder => configure(builder.Services), map);
    }

    private static void AddIdentityStack(IServiceCollection services)
    {
        services.AddIdentityApiEndpoints<TestAppUser>(identity =>
            {
                identity.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            })
            .AddEntityFrameworkStores<TestDbContext>();
        services.AddCookieAuthEndpoints();
        services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>(_ => { });
        services.AddPasskeyEndpoints<TestAppUser>();
        services.Configure<IdentityPasskeyOptions>(passkeys => passkeys.ServerDomain = "localhost");
        services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
        {
            jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
        });
    }

    private static Endpoint Find(WebApplication app, string methodAndPath)
    {
        return TryFind(app, methodAndPath)
            ?? throw new Xunit.Sdk.XunitException("Missing endpoint " + methodAndPath);
    }

    private static Endpoint? TryFind(WebApplication app, string methodAndPath)
    {
        foreach (var endpoint in ((IEndpointRouteBuilder)app).DataSources.SelectMany(source => source.Endpoints))
        {
            var methods = endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods;
            var method = methods is { Count: > 0 } ? string.Join(',', methods) : "*";
            var raw = endpoint is RouteEndpoint route
                ? route.RoutePattern.RawText ?? ""
                : endpoint.DisplayName ?? "";
            if (!raw.StartsWith('/'))
            {
                raw = "/" + raw;
            }

            if (string.Equals(method + " " + raw, methodAndPath, StringComparison.Ordinal))
            {
                return endpoint;
            }
        }

        return null;
    }

    private static string? HandlerName(Endpoint endpoint)
    {
        return endpoint.Metadata.GetMetadata<MethodInfo>()?.Name
            ?? endpoint.Metadata.OfType<MethodInfo>().FirstOrDefault()?.Name;
    }

    private static void AssertObsolete(MemberInfo member)
    {
        var obsolete = member.GetCustomAttribute<ObsoleteAttribute>();
        Assert.NotNull(obsolete);
        Assert.Contains("ISignInCompleter", obsolete.Message, StringComparison.Ordinal);
        Assert.Contains("AddSignInCompleter", obsolete.Message, StringComparison.Ordinal);
        Assert.Contains("Removed in 5.0", obsolete.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("o.SignIn.Completer", obsolete.Message, StringComparison.Ordinal);
    }

    private static async Task AssertSession(HttpResponseMessage response, SessionKind kind, bool passkeyRegister)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode} {body}");
        JsonDocument? doc = string.IsNullOrWhiteSpace(body) ? null : JsonDocument.Parse(body);
        var root = doc?.RootElement;
        var accessToken = root is { } tokenRoot ? TestHelpers.TryGetString(tokenRoot, "accessToken", "AccessToken") : null;
        var refreshToken = root is { } refreshRoot ? TestHelpers.TryGetString(refreshRoot, "refreshToken", "RefreshToken") : null;
        var tokenType = root is { } typeRoot ? TestHelpers.TryGetString(typeRoot, "tokenType", "TokenType") : null;
        var credentialId = root is { } credentialRoot ? TestHelpers.TryGetString(credentialRoot, "credentialId", "CredentialId") : null;
        var expiresIn = root is { } expiresRoot && expiresRoot.TryGetProperty("expiresIn", out var expires) && expires.ValueKind == JsonValueKind.Number;

        switch (kind)
        {
            case SessionKind.Cookie:
                Assert.True(string.IsNullOrEmpty(accessToken));
                Assert.True(string.IsNullOrEmpty(refreshToken));
                Assert.True(HasCookie(response, ".AspNetCore.Identity.Application"));
                Assert.False(HasCookie(response, RefreshTokenCookieWriter.CookieName));
                if (passkeyRegister)
                {
                    Assert.False(string.IsNullOrEmpty(credentialId));
                }
                else
                {
                    Assert.True(string.IsNullOrWhiteSpace(body));
                }

                break;
            case SessionKind.IdentityBearer:
                Assert.False(string.IsNullOrEmpty(accessToken));
                Assert.False(string.IsNullOrEmpty(refreshToken));
                Assert.Equal("Bearer", tokenType);
                Assert.True(expiresIn);
                Assert.True(string.IsNullOrEmpty(credentialId));
                Assert.False(HasCookie(response, ".AspNetCore.Identity.Application"));
                Assert.False(HasCookie(response, RefreshTokenCookieWriter.CookieName));
                break;
            case SessionKind.Jwt:
                Assert.False(string.IsNullOrEmpty(accessToken));
                Assert.True(string.IsNullOrEmpty(refreshToken));
                Assert.Equal("Bearer", tokenType);
                Assert.False(expiresIn);
                Assert.True(string.IsNullOrEmpty(credentialId));
                Assert.True(HasCookie(response, RefreshTokenCookieWriter.CookieName));
                Assert.False(HasCookie(response, ".AspNetCore.Identity.Application"));
                break;
        }

        doc?.Dispose();
    }

    private static bool HasCookie(HttpResponseMessage response, string name)
    {
        return response.Headers.TryGetValues("Set-Cookie", out var values)
            && values.Any(value => value.Contains(name, StringComparison.Ordinal));
    }

    private static async Task<string?> TitleAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return TestHelpers.TryGetString(doc.RootElement, "title", "Title");
    }

    private static async Task<string?> MarkerAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return TestHelpers.TryGetString(doc.RootElement, "marker", "Marker");
    }

    private static string WrongTotp(string key)
    {
        var current = TotpHelper.GenerateCode(key);
        return current == "000000" ? "111111" : "000000";
    }

    private static string UniqueEmail(string label) => $"{label}-{Guid.NewGuid():N}@test.local";

    private enum SessionKind
    {
        Cookie,
        IdentityBearer,
        Jwt,
    }

    private static class SignInMaps
    {
        public static void Sessions(WebApplication app)
        {
            Map(app, "/cookie", SignInCompleters.Cookie, "cookie");
            Map(app, "/bearer", SignInCompleters.IdentityBearer, "bearer");
            Map(app, "/jwt", SignInCompleters.Jwt, "jwt");
        }

        public static void Defaults(WebApplication app)
        {
            app.MapGroup("/default-cookie").MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.Cookie, "default-cookie-confirm");
            app.MapGroup("/default-bearer").MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.IdentityBearer, "default-bearer-confirm");
            app.MapGroup("/default-email").MapEmailCodeEndpoints<TestAppUser>();
            app.MapGroup("/default-passkey").MapPasskeySignInEndpoints<TestAppUser>("default-passkey-confirm");
        }

        public static void Named(WebApplication app, string name)
        {
            Map(app, "/password", name, "spy");
        }

        private static void Map(WebApplication app, string prefix, string completer, string name)
        {
            var group = app.MapGroup(prefix);
            group.MapPasswordEndpoints<TestAppUser>(completer, name + "-password-confirm");
            group.MapEmailCodeEndpoints<TestAppUser>(completer);
            group.MapPasskeySignInEndpoints<TestAppUser>(completer, name + "-passkey-confirm");
        }
    }
}

internal class SignInCompleterCounter
{
    public int Calls;
    public int Constructions;
}

internal sealed class KeyedSpyCounter : SignInCompleterCounter;

internal sealed class LegacyEmailCounter : SignInCompleterCounter;

internal sealed class LegacyPasskeyCounter : SignInCompleterCounter;

internal sealed class CountingSignInCompleter : ISignInCompleter<TestAppUser>
{
    private readonly KeyedSpyCounter _counter;

    public CountingSignInCompleter(KeyedSpyCounter counter)
    {
        _counter = counter;
        Interlocked.Increment(ref counter.Constructions);
    }

    public Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TestAppUser user,
        SignInCompletionContext context,
        CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _counter.Calls);
        return Task.FromResult<IResult>(TypedResults.Ok(new { marker = "keyed" }));
    }
}

internal sealed class AlphaCompleter : ISignInCompleter<TestAppUser>
{
    public Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TestAppUser user,
        SignInCompletionContext context,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IResult>(TypedResults.Empty);
}

internal sealed class OtherSignInUser;

internal sealed class OtherUserCompleter : ISignInCompleter<OtherSignInUser>
{
    public static int Constructions;

    public OtherUserCompleter()
    {
        Interlocked.Increment(ref Constructions);
    }

    public Task<IResult> CompleteAsync(
        HttpContext httpContext,
        OtherSignInUser user,
        SignInCompletionContext context,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IResult>(TypedResults.Empty);
}

internal sealed class BetaCompleter : ISignInCompleter<TestAppUser>
{
    public Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TestAppUser user,
        SignInCompletionContext context,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IResult>(TypedResults.Empty);
}

internal sealed class LegacyEmailCodeSpy : IEmailCodeSignInCompleter<TestAppUser>
{
    private readonly LegacyEmailCounter _counter;

    public LegacyEmailCodeSpy(LegacyEmailCounter counter)
    {
        _counter = counter;
    }

    public Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TestAppUser user,
        EmailCodeSignInContext context,
        CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _counter.Calls);
        return Task.FromResult<IResult>(TypedResults.Ok(new { marker = "email" }));
    }
}

internal sealed class LegacyPasskeySpy : IPasskeySignInCompleter<TestAppUser>
{
    private readonly LegacyPasskeyCounter _counter;

    public LegacyPasskeySpy(LegacyPasskeyCounter counter)
    {
        _counter = counter;
    }

    public Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TestAppUser user,
        PasskeySignInCompletionContext context,
        CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _counter.Calls);
        return Task.FromResult<IResult>(TypedResults.Ok(new { marker = "passkey" }));
    }
}

internal sealed class WarningLoggerProvider : ILoggerProvider
{
    public List<string> Messages { get; } = [];

    public ILogger CreateLogger(string categoryName) => new WarningLogger(Messages);

    public void Dispose()
    {
    }

    private sealed class WarningLogger : ILogger
    {
        private readonly List<string> _messages;

        public WarningLogger(List<string> messages)
        {
            _messages = messages;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= LogLevel.Warning)
            {
                _messages.Add(formatter(state, exception));
            }
        }
    }
}

internal sealed class SignInHost : IAsyncDisposable
{
    private readonly string _path;

    private SignInHost(
        WebApplication app,
        string path,
        CapturingEmailSender mail,
        ApiClient client,
        SoftwareWebAuthnAuthenticator authenticator,
        KeyedSpyCounter counter,
        LegacyEmailCounter legacyEmail,
        LegacyPasskeyCounter legacyPasskey)
    {
        App = app;
        _path = path;
        Mail = mail;
        Client = client;
        Authenticator = authenticator;
        Counter = counter;
        LegacyEmailCount = legacyEmail;
        LegacyPasskeyCount = legacyPasskey;
    }

    public WebApplication App { get; }

    public CapturingEmailSender Mail { get; }

    public ApiClient Client { get; }

    public SoftwareWebAuthnAuthenticator Authenticator { get; }

    public KeyedSpyCounter Counter { get; }

    public LegacyEmailCounter LegacyEmailCount { get; }

    public LegacyPasskeyCounter LegacyPasskeyCount { get; }

    public static async Task<SignInHost> StartAsync(Action<SignInHostOptions> configure)
    {
        var options = new SignInHostOptions();
        configure(options);
        var path = Path.Combine(Path.GetTempPath(), $"ae-signin-{Guid.NewGuid():N}.sqlite");
        var mail = new CapturingEmailSender();
        var authenticator = new SoftwareWebAuthnAuthenticator();
        var counter = new KeyedSpyCounter();
        var legacyEmail = new LegacyEmailCounter();
        var legacyPasskey = new LegacyPasskeyCounter();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(db => db.UseSqlite($"Data Source={path}"));
        builder.Services.AddSingleton<IEmailSender<TestAppUser>>(mail);
        builder.Services.AddSingleton<IEmailCodeSender<TestAppUser>>(mail);
        builder.Services.AddSingleton(authenticator);
        builder.Services.AddSingleton(counter);
        builder.Services.AddSingleton(legacyEmail);
        builder.Services.AddSingleton(legacyPasskey);
        builder.Services
            .AddIdentityApiEndpoints<TestAppUser>(identity =>
            {
                identity.SignIn.RequireConfirmedAccount = options.RequireConfirmedAccount;
                identity.SignIn.RequireConfirmedPhoneNumber = options.RequireConfirmedPhoneNumber;
                identity.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                identity.Password.RequireDigit = false;
                identity.Password.RequireLowercase = false;
                identity.Password.RequireUppercase = false;
                identity.Password.RequireNonAlphanumeric = false;
                identity.Password.RequiredLength = 6;
                if (options.MaxFailedAccessAttempts is int attempts)
                {
                    identity.Lockout.MaxFailedAccessAttempts = attempts;
                }
            })
            .AddEntityFrameworkStores<TestDbContext>()
            .AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.AddAntiforgery();
        builder.Services.AddCookieAuthEndpoints();
        builder.Services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>(email =>
        {
            email.ResendCooldown = TimeSpan.Zero;
            email.SendsPerIpPerMinute = 100;
        });
        builder.Services.AddPasskeyEndpoints<TestAppUser>();
        builder.Services.Configure<IdentityPasskeyOptions>(passkeys => passkeys.ServerDomain = "localhost");
        if (options.AddJwt)
        {
            builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            });
        }

        options.ConfigureServices?.Invoke(builder.Services);

        if (!string.IsNullOrWhiteSpace(options.DefaultCompleter))
        {
            builder.Services.Configure<SignInCompletionOptions>(completion => completion.Default = options.DefaultCompleter);
        }

        if (options.LegacyEmail)
        {
            builder.Services.AddEmailCodeSignInCompleter<TestAppUser, LegacyEmailCodeSpy>();
        }

        if (options.LegacyPasskey)
        {
            builder.Services.AddPasskeySignInCompleter<TestAppUser, LegacyPasskeySpy>();
        }

        if (options.SpyOnBuiltInNames)
        {
            builder.Services.AddSignInCompleter<TestAppUser, CountingSignInCompleter>(SignInCompleters.Cookie);
            builder.Services.AddSignInCompleter<TestAppUser, CountingSignInCompleter>(SignInCompleters.IdentityBearer);
            builder.Services.AddSignInCompleter<TestAppUser, CountingSignInCompleter>(SignInCompleters.Jwt);
        }
        else if (options.RegisterKeyedSpy)
        {
            builder.Services.AddSignInCompleter<TestAppUser, CountingSignInCompleter>(options.SpyName ?? "Spy");
        }

        var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();
        }

        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();
        app.MapGet("/csrfToken", (Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery, HttpContext http) =>
            Results.Ok(new { csrfToken = antiforgery.GetAndStoreTokens(http).RequestToken }));
        options.Map(app);
        await app.StartAsync();
        return new SignInHost(app, path, mail, new ApiClient(app), authenticator, counter, legacyEmail, legacyPasskey);
    }

    public async Task<TestAppUser> SeedAsync(string email, bool confirmed = true, bool twoFactor = false, bool locked = false)
    {
        using var scope = App.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = new TestAppUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = confirmed,
        };
        var created = await users.CreateAsync(user, TestHelpers.DefaultPassword);
        Assert.True(created.Succeeded, string.Join("; ", created.Errors.Select(error => error.Description)));
        if (twoFactor)
        {
            Assert.True((await users.ResetAuthenticatorKeyAsync(user)).Succeeded);
            Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
        }

        if (locked)
        {
            await LockAsync(email);
        }

        return user;
    }

    public async Task LockAsync(string email)
    {
        using var scope = App.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await users.FindByEmailAsync(email);
        Assert.NotNull(user);
        Assert.True((await users.SetLockoutEnabledAsync(user, true)).Succeeded);
        Assert.True((await users.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddHours(1))).Succeeded);
    }

    public async Task<string> AuthenticatorKeyAsync(string email)
    {
        using var scope = App.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var user = await users.FindByEmailAsync(email);
        Assert.NotNull(user);
        var key = await users.GetAuthenticatorKeyAsync(user);
        Assert.False(string.IsNullOrEmpty(key));
        return key;
    }

    public string Code(string email)
    {
        return Mail.Snapshot().Last(item => item.Kind == "email-code" && item.Email == email).Body;
    }

    public async Task<(HttpResponseMessage Response, string CredentialId)> RegisterPasskeyAsync(string prefix, string email)
    {
        var options = await Client.PostAsync(prefix + "/register/options", new { email }, csrf: true);
        Assert.Equal(HttpStatusCode.OK, options.StatusCode);
        var credentialJson = Authenticator.CreateAttestation(await options.Content.ReadAsStringAsync(), Client.Origin);
        using var created = JsonDocument.Parse(credentialJson);
        var credentialId = created.RootElement.GetProperty("id").GetString()!;
        var response = await Client.PostAsync(prefix + "/register", new { email, credentialJson }, csrf: true);
        return (response, credentialId);
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

internal sealed class SignInHostOptions
{
    public bool RequireConfirmedAccount { get; set; }

    public bool RequireConfirmedPhoneNumber { get; set; }

    public bool AddJwt { get; set; } = true;

    public string? DefaultCompleter { get; set; }

    public bool RegisterKeyedSpy { get; set; }

    public bool SpyOnBuiltInNames { get; set; }

    public string? SpyName { get; set; }

    public bool LegacyEmail { get; set; }

    public bool LegacyPasskey { get; set; }

    public int? MaxFailedAccessAttempts { get; set; }

    public Action<IServiceCollection>? ConfigureServices { get; set; }

    public Action<WebApplication> Map { get; set; } = static _ => { };
}

internal sealed class ApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly System.Net.CookieContainer _cookies = new();

    public ApiClient(WebApplication app)
    {
        _http = app.GetTestClient();
        Base = _http.BaseAddress ?? new Uri("http://localhost/");
        Origin = Base.GetLeftPart(UriPartial.Authority);
    }

    public Uri Base { get; }

    public string Origin { get; }

    public Task<HttpResponseMessage> PostAsync(string url, object? body, bool csrf = false)
        => SendAsync(HttpMethod.Post, url, body, csrf);

    public void Dispose() => _http.Dispose();

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string url, object? body, bool csrf)
    {
        string? token = null;
        if (csrf)
        {
            token = await CsrfAsync();
        }

        using var request = new HttpRequestMessage(method, url)
        {
            Content = body is null ? null : JsonContent.Create(body),
        };
        Apply(request);
        if (token is not null)
        {
            request.Headers.TryAddWithoutValidation("RequestVerificationToken", token);
        }

        request.Headers.TryAddWithoutValidation("Origin", Origin);
        var response = await _http.SendAsync(request);
        Capture(response);
        return response;
    }

    private async Task<string> CsrfAsync()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/csrfToken");
        Apply(request);
        var response = await _http.SendAsync(request);
        Capture(response);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return TestHelpers.TryGetString(doc.RootElement, "csrfToken", "CsrfToken")!;
    }

    private void Apply(HttpRequestMessage request)
    {
        var header = _cookies.GetCookieHeader(Base);
        if (!string.IsNullOrEmpty(header))
        {
            request.Headers.TryAddWithoutValidation("Cookie", header);
        }
    }

    private void Capture(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return;
        }

        foreach (var value in values)
        {
            _cookies.SetCookies(Base, value);
        }
    }
}
