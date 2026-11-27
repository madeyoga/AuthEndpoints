using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Tests.PublicApi;

/// <summary>
/// Route surface of <c>AddAuthEndpoints</c> / <c>MapAuthEndpoints</c>. Each snapshot is also compared with the
/// documented building-block expansion, so the builder stays a thin layer over the blocks.
/// </summary>
public class AuthEndpointsBuilderRouteTests
{
    private const string SigningKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";

    [Fact]
    public Task Cookie_Password()
    {
        var surface = CaptureBuilder(AuthEndpointsSession.Cookie, passkeys: false);
        Assert.Equal(surface, CaptureBlocks(AuthEndpointsSession.Cookie, passkeys: false));
        Assert.Contains("POST /auth/register", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/login", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/logout", surface, StringComparison.Ordinal);
        Assert.Contains("GET /auth/csrfToken", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/forgotPassword", surface, StringComparison.Ordinal);
        Assert.Contains("GET /auth/confirmEmail", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/resendConfirmationEmail", surface, StringComparison.Ordinal);
        Assert.Contains("GET /auth/manage/info", surface, StringComparison.Ordinal);
        Assert.Contains("GET /auth/manage/2fa", surface, StringComparison.Ordinal);
        Assert.Contains("GET /auth/manage/authMethods", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/confirmIdentity", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/manage/password", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("/passkeys", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("passkeyOptions", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("emailCode", surface, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("/auth/create", surface, StringComparison.Ordinal);
        return Verifier.Verify(surface);
    }

    [Fact]
    public Task Cookie_PasswordPasskeys()
    {
        var surface = CaptureBuilder(AuthEndpointsSession.Cookie, passkeys: true);
        Assert.Equal(surface, CaptureBlocks(AuthEndpointsSession.Cookie, passkeys: true));
        Assert.Contains("POST /auth/passkeys/login", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/passkeys/register", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/passkeys/requestOptions", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/passkeys/register/options", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/confirmIdentity/passkeyOptions", surface, StringComparison.Ordinal);
        Assert.Contains("GET /auth/passkeys/", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("emailCode", surface, StringComparison.OrdinalIgnoreCase);
        return Verifier.Verify(surface);
    }

    [Fact]
    public Task Jwt_Password()
    {
        var surface = CaptureBuilder(AuthEndpointsSession.Jwt, passkeys: false);
        Assert.Equal(surface, CaptureBlocks(AuthEndpointsSession.Jwt, passkeys: false));
        Assert.Contains("POST /auth/create", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/refresh", surface, StringComparison.Ordinal);
        Assert.Contains("GET /auth/verify", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/logout", surface, StringComparison.Ordinal);
        Assert.Contains("GET /auth/csrfToken", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/register", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/manage/password", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("POST /auth/login", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("/passkeys", surface, StringComparison.Ordinal);
        return Verifier.Verify(surface);
    }

    [Fact]
    public Task Jwt_PasswordPasskeys()
    {
        var surface = CaptureBuilder(AuthEndpointsSession.Jwt, passkeys: true);
        Assert.Equal(surface, CaptureBlocks(AuthEndpointsSession.Jwt, passkeys: true));
        Assert.Contains("POST /auth/passkeys/login", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/passkeys/register", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/create", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("POST /auth/login", surface, StringComparison.Ordinal);
        return Verifier.Verify(surface);
    }

    [Fact]
    public Task IdentityBearer_Password()
    {
        var surface = CaptureBuilder(AuthEndpointsSession.IdentityBearer, passkeys: false);
        Assert.Equal(surface, CaptureBlocks(AuthEndpointsSession.IdentityBearer, passkeys: false));
        Assert.Contains("POST /auth/login", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/refresh", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/logout", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("GET /auth/csrfToken", surface, StringComparison.Ordinal);
        return Verifier.Verify(surface);
    }

    [Fact]
    public Task Cookie_EmailCodeOnly()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>().AddEmailCode();
                builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
            },
            app => app.MapAuthEndpoints<TestAppUser>("/auth", AuthEndpointsSession.Cookie));

        Assert.Contains("POST /auth/emailCode/send", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/emailCode/verify", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/confirmIdentity/emailCode/send", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/logout", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("POST /auth/login", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("POST /auth/register", surface, StringComparison.Ordinal);
        return Verifier.Verify(surface);
    }

    [Fact]
    public void Passkeys_WithoutSignUp_MapPasskeyOptions_AndNoPasskeyRegistration()
    {
        // The #475 setup: password plus passkey sign-in and management, without anonymous sign-up.
        var surface = RouteSurface.Capture(
            builder =>
            {
                builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>()
                    .AddPassword()
                    .AddPasskeys(passkeys => passkeys.SignUp = false);
                builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
            },
            app => app.MapAuthEndpoints<TestAppUser>("/auth", AuthEndpointsSession.Cookie));

        Assert.Contains("POST /auth/confirmIdentity/passkeyOptions", surface, StringComparison.Ordinal);
        Assert.Contains("POST /auth/passkeys/login", surface, StringComparison.Ordinal);
        Assert.Contains("GET /auth/passkeys/", surface, StringComparison.Ordinal);
        Assert.Contains("DELETE /auth/manage/password", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("/passkeys/register", surface, StringComparison.Ordinal);
    }

    [Fact]
    public void Password_WithoutSignUpOrRecovery_MapsOnlySignIn()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>()
                    .AddPassword(password =>
                    {
                        password.SignUp = false;
                        password.Recovery = false;
                    });
                builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
            },
            app => app.MapAuthEndpoints<TestAppUser>("/auth", AuthEndpointsSession.Cookie));

        Assert.Contains("POST /auth/login", surface, StringComparison.Ordinal);
        Assert.Contains("GET /auth/confirmEmail", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("POST /auth/register", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("forgotPassword", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("resetPassword", surface, StringComparison.Ordinal);
    }

    [Fact]
    public void Jwt_BodyRefresh_OmitsCsrfAndMatchesBlocks()
    {
        var surface = CaptureBuilder(AuthEndpointsSession.Jwt, passkeys: false, RefreshTokenTransport.Body);
        Assert.Equal(surface, CaptureBlocks(AuthEndpointsSession.Jwt, passkeys: false, RefreshTokenTransport.Body));
        Assert.DoesNotContain("GET /auth/csrfToken", surface, StringComparison.Ordinal);
        Assert.Contains(
            "POST /auth/logout name=(none) auth=(none) antiforgery=false",
            surface,
            StringComparison.Ordinal);
        Assert.Contains(
            "POST /auth/refresh name=(none) auth=(none) antiforgery=false",
            surface,
            StringComparison.Ordinal);
    }

    [Fact]
    public void AddJwtEndpoints_HonoursRefreshTokenTransport()
    {
        using var app = RouteSurface.Build(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
                {
                    jwt.SigningOptions.SymmetricKey = SigningKey;
                    jwt.RefreshTokenTransport = RefreshTokenTransport.Body;
                });
            },
            app => app.MapGroup("/auth").MapJwtSessionEndpoints<TestAppUser>());

        Assert.Equal(
            RefreshTokenTransport.Body,
            app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<SimpleJwtOptions>>().Value.RefreshTokenTransport);
        var routes = RouteSurface.ListRoutes(app);
        Assert.DoesNotContain(routes, route => route.Contains("csrfToken", StringComparison.Ordinal));
        var refresh = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>()
            .Single(endpoint => endpoint.RoutePattern.RawText == "/auth/refresh");
        Assert.DoesNotContain(refresh.Metadata.GetOrderedMetadata<IAntiforgeryMetadata>(), metadata => metadata.RequiresValidation);
    }

    [Fact]
    public void AddJwtEndpoints_RejectsUnknownRefreshTokenTransport()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        builder.Services.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase("jwt-transport-" + Guid.NewGuid().ToString("N")));
        var ex = Assert.ThrowsAny<Exception>(() =>
            builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
            {
                jwt.SigningOptions.SymmetricKey = SigningKey;
                jwt.RefreshTokenTransport = (RefreshTokenTransport)9;
            }));
        Assert.Contains("RefreshTokenTransport", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void JwtSessionSettings_ComeFromTheAddJwtEndpointsCallback()
    {
        using var app = RouteSurface.Build(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
                {
                    jwt.SigningOptions.SymmetricKey = SigningKey;
                    jwt.RefreshTokenTransport = RefreshTokenTransport.Body;
                    jwt.RefreshTokenLifetime = TimeSpan.FromDays(2);
                    jwt.AbsoluteLifetime = TimeSpan.FromDays(7);
                });
            },
            app => app.MapGroup("/auth").MapJwtSessionEndpoints<TestAppUser>());

        var jwt = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<SimpleJwtOptions>>().Value;
        Assert.Equal(RefreshTokenTransport.Body, jwt.RefreshTokenTransport);
        Assert.Equal(TimeSpan.FromDays(2), jwt.RefreshTokenLifetime);
        Assert.Equal(TimeSpan.FromDays(7), jwt.AbsoluteLifetime);
        Assert.DoesNotContain("csrfToken", string.Join('\n', RouteSurface.ListRoutes(app)), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("RefreshTokenLifetime")]
    [InlineData("AbsoluteLifetime")]
    public void AddJwtEndpoints_RejectsANonPositiveSessionLifetime(string property)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development,
        });
        var ex = Assert.Throws<Microsoft.Extensions.Options.OptionsValidationException>(() =>
            builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
            {
                jwt.SigningOptions.SymmetricKey = SigningKey;
                if (property == "RefreshTokenLifetime")
                {
                    jwt.RefreshTokenLifetime = TimeSpan.Zero;
                }
                else
                {
                    jwt.AbsoluteLifetime = TimeSpan.Zero;
                }
            }));
        Assert.Contains($"SimpleJwtOptions.{property} must be greater than zero.", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MapAuthEndpoints_PlusBuildingBlockOnSamePrefix_Warns()
    {
        var logs = new WarningLog();
        var surface = RouteSurface.Capture(
            builder =>
            {
                builder.Logging.AddProvider(logs);
                builder.Logging.SetMinimumLevel(LogLevel.Warning);
                AddBuilder(builder.Services, AuthEndpointsSession.Cookie, passkeys: false, transport: null);
            },
            app =>
            {
                app.MapAuthEndpoints<TestAppUser>("/auth", AuthEndpointsSession.Cookie);
                app.MapGroup("/auth").MapPasswordSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
            });

        Assert.Contains("POST /auth/login", surface, StringComparison.Ordinal);
        Assert.Contains(
            logs.Messages,
            message => message.Contains("both map POST /auth/login", StringComparison.Ordinal));
    }

    [Fact]
    public void CustomPath_PrefixesEveryRoute()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>().AddPassword();
                builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
            },
            app => app.MapAuthEndpoints<TestAppUser>("/sign-in", AuthEndpointsSession.Cookie));

        Assert.Contains("POST /sign-in/register", surface, StringComparison.Ordinal);
        Assert.Contains("POST /sign-in/login", surface, StringComparison.Ordinal);
        Assert.Contains("GET /sign-in/csrfToken", surface, StringComparison.Ordinal);
        Assert.Contains("GET /sign-in/manage/info", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("/auth/", surface, StringComparison.Ordinal);
    }

    private static string CaptureBuilder(
        AuthEndpointsSession session,
        bool passkeys,
        RefreshTokenTransport? transport = null)
    {
        return RouteSurface.Capture(
            builder => AddBuilder(builder.Services, session, passkeys, transport),
            app => app.MapAuthEndpoints<TestAppUser>("/auth", session));
    }

    private static string CaptureBlocks(
        AuthEndpointsSession session,
        bool passkeys,
        RefreshTokenTransport? transport = null)
    {
        return RouteSurface.Capture(
            builder => AddBlocks(builder.Services, session, passkeys, transport),
            app =>
            {
                var group = app.MapGroup("/auth");
                group.MapSignInEndpoints<TestAppUser>(session);
                group.MapSharedAuthEndpoints<TestAppUser>();
            });
    }

    private static void AddIdentity(WebApplicationBuilder builder)
    {
        builder.Services
            .AddIdentityApiEndpoints<TestAppUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = true;
                options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            })
            .AddEntityFrameworkStores<TestDbContext>()
            .AddDefaultTokenProviders();
    }

    private static void AddBuilder(
        IServiceCollection services,
        AuthEndpointsSession session,
        bool passkeys,
        RefreshTokenTransport? transport)
    {
        var auth = services.AddAuthEndpoints<TestAppUser, TestDbContext>().AddPassword();
        if (passkeys)
        {
            auth.AddPasskeys(o => o.ServerDomain = "localhost");
        }

        if (session == AuthEndpointsSession.Jwt)
        {
            auth.AddJwt(jwt => ConfigureJwt(jwt, transport));
        }
        else if (session == AuthEndpointsSession.IdentityBearer)
        {
            auth.AddIdentityBearer();
        }

        services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
    }

    /// <summary>
    /// Documented building-block expansion of <c>AddAuthEndpoints().AddPassword()</c> and
    /// <c>AddPasskeys()</c>. Keep this list aligned with the builder page.
    /// </summary>
    private static void AddBlocks(
        IServiceCollection services,
        AuthEndpointsSession session,
        bool passkeys,
        RefreshTokenTransport? transport)
    {
        services.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>();
        services.AddCookieSessionEndpoints();
        services.AddAccountManagementEndpoints();
        services.AddPasswordSignInEndpoints();
        services.AddPasswordSignUpEndpoints();
        services.AddPasswordRecoveryEndpoints();

        if (passkeys)
        {
            services.AddPasskeySignInEndpoints<TestAppUser>();
            services.AddPasskeySignUpEndpoints<TestAppUser>();
            services.AddPasskeyRegisterOptionsEndpoints();
            services.AddPasskeyManagementEndpoints();
            services.Configure<IdentityPasskeyOptions>(o => o.ServerDomain = "localhost");
        }

        if (session == AuthEndpointsSession.Jwt)
        {
            services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt => ConfigureJwt(jwt, transport));
        }
        else if (session == AuthEndpointsSession.IdentityBearer)
        {
            services.AddBearerSessionEndpoints();
        }

        services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
    }

    private static void ConfigureJwt(SimpleJwtOptions jwt, RefreshTokenTransport? transport)
    {
        jwt.SigningOptions.SymmetricKey = SigningKey;
        if (transport is not null)
        {
            jwt.RefreshTokenTransport = transport.Value;
        }
    }

    private static string Normalize(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal).TrimEnd() + "\n";

    private sealed class WarningLog : ILoggerProvider
    {
        public List<string> Messages { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Logger(categoryName, Messages);

        public void Dispose()
        {
        }

        private sealed class Logger(string category, List<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) =>
                logLevel >= LogLevel.Warning && category == AuthEndpointsModules.LogCategory;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (!IsEnabled(logLevel))
                {
                    return;
                }

                messages.Add(formatter(state, exception));
            }
        }
    }
}
