using AuthEndpoints.Identity;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Tests.PublicApi;

/// <summary>
/// A map that leaves a route out logs one line saying which routes and which <c>Add*</c> call maps them (#476 item 2).
/// </summary>
public class SkippedRouteLogTests
{
    private const string SigningKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";

    [Fact]
    public void BuilderWithPasswordOnly_LogsEachSkippedFeature_AndNothingItMapped()
    {
        var log = Map(
            auth => auth.AddPassword(),
            app => app.MapAuthEndpoints<TestAppUser>("/auth", AuthEndpointsSession.Cookie));

        Assert.Equal(
            [
                "Skipped POST /emailCode/verify: email-code sign-in is not registered. Call AddEmailCode on AddAuthEndpoints, or AddEmailCodeSignInEndpoints.",
                "Skipped POST /passkeys/requestOptions, POST /passkeys/login: passkey sign-in is not registered. Call AddPasskeys on AddAuthEndpoints, or AddPasskeySignInEndpoints.",
                "Skipped POST /passkeys/register: passkey sign-up is not registered. Call AddPasskeys with SignUp on, or AddPasskeySignUpEndpoints.",
                "Skipped POST /emailCode/send: email-code send is not registered. Call AddEmailCode on AddAuthEndpoints, or AddEmailCodeSendEndpoints.",
                "Skipped POST /passkeys/register/options: passkey sign-up is not registered. Call AddPasskeys with SignUp on, or AddPasskeyRegisterOptionsEndpoints.",
                "Skipped GET /passkeys, POST /passkeys/creationOptions, POST /passkeys, PATCH /passkeys, DELETE /passkeys/{credentialIdUrl}: passkey management is not registered. Call AddPasskeys with Management on, or AddPasskeyManagementEndpoints.",
                "Skipped POST /confirmIdentity/emailCode/send: email-code send is not registered, so an email code cannot confirm identity. Call AddEmailCode on AddAuthEndpoints, or AddEmailCodeSendEndpoints.",
                "Skipped POST /confirmIdentity/passkeyOptions: passkey sign-in and passkey management are not registered, so a passkey cannot confirm identity. Call AddPasskeys on AddAuthEndpoints, AddPasskeySignInEndpoints, or AddPasskeyManagementEndpoints.",
            ],
            log.Messages);
        Assert.All(log.Entries, entry =>
        {
            Assert.Equal(LogLevel.Information, entry.Level);
            Assert.Equal(new EventId(1001, "RouteSkipped"), entry.EventId);
        });
    }

    [Fact]
    public void BuilderWithEveryFeature_LogsNothing()
    {
        var log = Map(
            auth => auth.AddPassword().AddPasskeys().AddEmailCode(),
            app => app.MapAuthEndpoints<TestAppUser>("/auth", AuthEndpointsSession.Cookie));

        Assert.Empty(log.Messages);
    }

    [Fact]
    public void PartialFeatures_LogOnlyTheRoutesTheyLeaveOut()
    {
        var log = Map(
            auth => auth
                .AddPassword(password => password.Recovery = false)
                .AddPasskeys(passkeys =>
                {
                    passkeys.SignUp = false;
                    passkeys.Management = false;
                })
                .AddEmailCode(),
            app => app.MapAuthEndpoints<TestAppUser>("/auth", AuthEndpointsSession.Cookie));

        Assert.Equal(
            [
                "POST /passkeys/register",
                "POST /forgotPassword, POST /resetPassword",
                "POST /passkeys/register/options",
                "GET /passkeys, POST /passkeys/creationOptions, POST /passkeys, PATCH /passkeys, DELETE /passkeys/{credentialIdUrl}",
            ],
            log.Routes);
    }

    [Fact]
    public void JwtSession_NamesItsPasswordRoute()
    {
        var log = Map(
            auth => auth.AddEmailCode().AddJwt(jwt => jwt.SigningOptions.SymmetricKey = SigningKey),
            app => app.MapAuthEndpoints<TestAppUser>("/auth", AuthEndpointsSession.Jwt));

        Assert.Contains("POST /create", log.Routes);
        Assert.DoesNotContain("POST /login", log.Routes);
    }

    [Fact]
    public void AccountManagementWithoutPasskeys_ExplainsTheMissingPasskeyOptions()
    {
        // The #475 report: the reporter had to read source to learn why passkeyOptions was missing.
        var log = new LogCapture();
        using var app = RouteSurface.Build(builder =>
        {
            Capture(builder, log);
            builder.Services
                .AddIdentityApiEndpoints<TestAppUser>(options =>
                    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
                .AddEntityFrameworkStores<TestDbContext>()
                .AddDefaultTokenProviders();
            builder.Services.AddAccountManagementEndpoints();
        }, app => app.MapGroup("/identity").MapAccountManagementEndpoints<TestAppUser>());

        Assert.Contains("POST /confirmIdentity/passkeyOptions", log.Routes);

        var withPasskeySignIn = new LogCapture();
        using var signIn = RouteSurface.Build(builder =>
        {
            Capture(builder, withPasskeySignIn);
            builder.Services
                .AddIdentityApiEndpoints<TestAppUser>(options =>
                    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
                .AddEntityFrameworkStores<TestDbContext>()
                .AddDefaultTokenProviders();
            builder.Services.AddAccountManagementEndpoints();
            builder.Services.AddPasskeySignInEndpoints<TestAppUser>();
        }, app => app.MapGroup("/identity").MapAccountManagementEndpoints<TestAppUser>());

        Assert.DoesNotContain("POST /confirmIdentity/passkeyOptions", withPasskeySignIn.Routes);
    }

    [Fact]
    public void RaisingTheCategoryLevel_SilencesTheLines()
    {
        var log = Map(
            auth => auth.AddPassword(),
            app => app.MapAuthEndpoints<TestAppUser>("/auth", AuthEndpointsSession.Cookie),
            builder => builder.Logging.AddFilter(SkippedRoutes.LogCategory, LogLevel.Warning));

        Assert.Empty(log.Messages);
    }

    private static LogCapture Map(
        Action<AuthEndpointsBuilder> add,
        Action<WebApplication> map,
        Action<WebApplicationBuilder>? configure = null)
    {
        var log = new LogCapture();
        using var app = RouteSurface.Build(builder =>
        {
            Capture(builder, log);
            configure?.Invoke(builder);
            add(builder.Services.AddAuthEndpoints<TestAppUser>().AddEntityFrameworkStores<TestDbContext>());
            builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
        }, map);
        return log;
    }

    /// <remarks>The test project's appsettings.json sets the default level to Warning.</remarks>
    private static void Capture(WebApplicationBuilder builder, LogCapture log)
    {
        builder.Logging.AddProvider(log);
        builder.Logging.AddFilter(SkippedRoutes.LogCategory, LogLevel.Information);
    }

    private sealed record Entry(LogLevel Level, EventId EventId, string Message);

    private sealed class LogCapture : ILoggerProvider
    {
        public List<Entry> Entries { get; } = [];

        public IReadOnlyList<string> Messages => Entries.Select(entry => entry.Message).ToList();

        /// <summary>The routes part of each line: between "Skipped " and the first ": ".</summary>
        public IReadOnlyList<string> Routes => Messages
            .Select(message => message["Skipped ".Length..message.IndexOf(": ", StringComparison.Ordinal)])
            .ToList();

        public ILogger CreateLogger(string categoryName) => new Logger(categoryName, Entries);

        public void Dispose()
        {
        }

        private sealed class Logger(string category, List<Entry> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => category == SkippedRoutes.LogCategory;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (IsEnabled(logLevel))
                {
                    entries.Add(new Entry(logLevel, eventId, formatter(state, exception)));
                }
            }
        }
    }
}
