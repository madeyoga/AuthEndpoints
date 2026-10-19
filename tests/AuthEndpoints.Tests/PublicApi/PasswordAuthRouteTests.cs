using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Tests.PublicApi;

public class PasswordAuthRouteTests
{
    private const string SigningKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";

    [Fact]
    public Task Cookie_PasskeysOff()
    {
        var facade = CaptureFacade(AuthEndpointsSession.Cookie, passkeys: false);
        Assert.Equal(facade, CaptureBlocks(AuthEndpointsSession.Cookie, passkeys: false));
        Assert.Contains("POST /auth/register", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/login", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/logout", facade, StringComparison.Ordinal);
        Assert.Contains("GET /auth/csrfToken", facade, StringComparison.Ordinal);
        Assert.Contains("GET /auth/confirmEmail", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/resendConfirmationEmail", facade, StringComparison.Ordinal);
        Assert.Contains("GET /auth/manage/info", facade, StringComparison.Ordinal);
        Assert.Contains("GET /auth/manage/2fa", facade, StringComparison.Ordinal);
        Assert.Contains("GET /auth/manage/authMethods", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/confirmIdentity", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/manage/password", facade, StringComparison.Ordinal);
        Assert.DoesNotContain("/passkeys", facade, StringComparison.Ordinal);
        Assert.DoesNotContain("emailCode", facade, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("/auth/create", facade, StringComparison.Ordinal);
        Assert.DoesNotContain("/identity/", facade, StringComparison.Ordinal);
        return Verifier.Verify(facade);
    }

    [Fact]
    public Task Cookie_PasskeysOn()
    {
        var facade = CaptureFacade(AuthEndpointsSession.Cookie, passkeys: true);
        Assert.Equal(facade, CaptureBlocks(AuthEndpointsSession.Cookie, passkeys: true));
        Assert.Contains("POST /auth/passkeys/login", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/passkeys/register", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/passkeys/requestOptions", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/passkeys/register/options", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/confirmIdentity/passkeyOptions", facade, StringComparison.Ordinal);
        Assert.Contains("GET /auth/passkeys/", facade, StringComparison.Ordinal);
        Assert.DoesNotContain("emailCode", facade, StringComparison.OrdinalIgnoreCase);
        return Verifier.Verify(facade);
    }

    [Fact]
    public Task Jwt_PasskeysOff()
    {
        var facade = CaptureFacade(AuthEndpointsSession.Jwt, passkeys: false);
        Assert.Equal(facade, CaptureBlocks(AuthEndpointsSession.Jwt, passkeys: false));
        Assert.Contains("POST /auth/create", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/refresh", facade, StringComparison.Ordinal);
        Assert.Contains("GET /auth/verify", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/logout", facade, StringComparison.Ordinal);
        Assert.Contains("GET /auth/csrfToken", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/register", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/manage/password", facade, StringComparison.Ordinal);
        Assert.DoesNotContain("POST /auth/login", facade, StringComparison.Ordinal);
        Assert.DoesNotContain("/passkeys", facade, StringComparison.Ordinal);
        Assert.DoesNotContain("emailCode", facade, StringComparison.OrdinalIgnoreCase);
        return Verifier.Verify(facade);
    }

    [Fact]
    public Task Jwt_PasskeysOn()
    {
        var facade = CaptureFacade(AuthEndpointsSession.Jwt, passkeys: true);
        Assert.Equal(facade, CaptureBlocks(AuthEndpointsSession.Jwt, passkeys: true));
        Assert.Contains("POST /auth/passkeys/login", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/passkeys/register", facade, StringComparison.Ordinal);
        Assert.Contains("POST /auth/create", facade, StringComparison.Ordinal);
        Assert.DoesNotContain("POST /auth/login", facade, StringComparison.Ordinal);
        Assert.DoesNotContain("emailCode", facade, StringComparison.OrdinalIgnoreCase);
        return Verifier.Verify(facade);
    }

    [Fact]
    public void Jwt_BodyRefresh_OmitsCsrfAndMatchesBlocks()
    {
        var facade = CaptureFacade(AuthEndpointsSession.Jwt, passkeys: false, RefreshTokenTransport.Body);
        Assert.Equal(facade, CaptureBlocks(AuthEndpointsSession.Jwt, passkeys: false, RefreshTokenTransport.Body));
        Assert.DoesNotContain("GET /auth/csrfToken", facade, StringComparison.Ordinal);
        Assert.Contains(
            "POST /auth/logout name=(none) auth=(none) antiforgery=false",
            facade,
            StringComparison.Ordinal);
        Assert.Contains(
            "POST /auth/refresh name=(none) auth=(none) antiforgery=false",
            facade,
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
            app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<JwtSessionOptions>>().Value.RefreshTokenTransport);
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
    public void ConfigureJwtSessionOptions_BeforeAddJwtEndpoints_KeepsBodyWhenJwtOptionsStayCookie()
    {
        using var app = RouteSurface.Build(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.Configure<JwtSessionOptions>(session =>
                    session.RefreshTokenTransport = RefreshTokenTransport.Body);
                builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
                    jwt.SigningOptions.SymmetricKey = SigningKey);
            },
            app => app.MapGroup("/auth").MapJwtSessionEndpoints<TestAppUser>());

        Assert.Equal(
            RefreshTokenTransport.Body,
            app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<JwtSessionOptions>>().Value.RefreshTokenTransport);
        Assert.DoesNotContain(
            "csrfToken",
            string.Join('\n', RouteSurface.ListRoutes(app)),
            StringComparison.Ordinal);
    }

    [Fact]
    public void AddJwtEndpoints_BodyTransport_ReplacesEarlierCookieConfigure()
    {
        using var app = RouteSurface.Build(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.Configure<JwtSessionOptions>(session =>
                    session.RefreshTokenTransport = RefreshTokenTransport.Cookie);
                builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
                {
                    jwt.SigningOptions.SymmetricKey = SigningKey;
                    jwt.RefreshTokenTransport = RefreshTokenTransport.Body;
                });
            },
            app => app.MapGroup("/auth").MapJwtSessionEndpoints<TestAppUser>());

        Assert.Equal(
            RefreshTokenTransport.Body,
            app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<JwtSessionOptions>>().Value.RefreshTokenTransport);
    }

    [Fact]
    public void ConfigureJwtSessionOptions_AfterAddJwtEndpoints_ReplacesTransport()
    {
        using var app = RouteSurface.Build(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.AddAntiforgery();
                builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
                {
                    jwt.SigningOptions.SymmetricKey = SigningKey;
                    jwt.RefreshTokenTransport = RefreshTokenTransport.Body;
                });
                builder.Services.Configure<JwtSessionOptions>(session =>
                    session.RefreshTokenTransport = RefreshTokenTransport.Cookie);
            },
            app => app.MapGroup("/auth").MapJwtSessionEndpoints<TestAppUser>());

        Assert.Equal(
            RefreshTokenTransport.Cookie,
            app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<JwtSessionOptions>>().Value.RefreshTokenTransport);
        Assert.Contains("GET /auth/csrfToken", string.Join('\n', RouteSurface.ListRoutes(app)), StringComparison.Ordinal);
    }

    [Fact]
    public void FrozenFacade_DefaultJwtTransport_StaysCookie()
    {
        using var app = RouteSurface.Build(
            builder =>
            {
                builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(o =>
                {
                    o.Passkeys.Enabled = false;
                    o.Jwt.Enabled = true;
                    o.Jwt.Configure = jwt => jwt.SigningOptions.SymmetricKey = SigningKey;
                });
                builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
            },
            app => app.MapAuthEndpoints<TestAppUser>());

        Assert.Equal(
            RefreshTokenTransport.Cookie,
            app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<JwtSessionOptions>>().Value.RefreshTokenTransport);
        Assert.Contains("GET /auth/csrfToken", string.Join('\n', RouteSurface.ListRoutes(app)), StringComparison.Ordinal);
    }

    [Fact]
    public void FrozenFacade_BodyTransport_IsHonoured()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(o =>
                {
                    o.Passkeys.Enabled = false;
                    o.Jwt.Enabled = true;
                    o.Jwt.Configure = jwt =>
                    {
                        jwt.SigningOptions.SymmetricKey = SigningKey;
                        jwt.RefreshTokenTransport = RefreshTokenTransport.Body;
                    };
                });
                builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
            },
            app => app.MapAuthEndpoints<TestAppUser>());

        Assert.DoesNotContain("GET /auth/csrfToken", surface, StringComparison.Ordinal);
        Assert.Contains("GET /identity/csrfToken", surface, StringComparison.Ordinal);
        Assert.Contains(
            "POST /auth/refresh name=(none) auth=(none) antiforgery=false",
            surface,
            StringComparison.Ordinal);
    }

    [Fact]
    public void MapPasswordAuth_PlusBuildingBlockOnSamePrefix_Warns()
    {
        var logs = new WarningLog();
        var surface = RouteSurface.Capture(
            builder =>
            {
                builder.Logging.AddProvider(logs);
                builder.Logging.SetMinimumLevel(LogLevel.Warning);
                AddFacade(builder.Services, AuthEndpointsSession.Cookie, passkeys: false, transport: null);
            },
            app =>
            {
                app.MapPasswordAuth<TestAppUser>();
                app.MapGroup("/auth").MapPasswordSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
            });

        Assert.Contains("POST /auth/login", surface, StringComparison.Ordinal);
        Assert.Contains(
            logs.Messages,
            message => message.Contains("both map POST /auth/login", StringComparison.Ordinal));
    }

    [Fact]
    public void CustomPath_PrefixesEveryPasswordRoute()
    {
        var surface = RouteSurface.Capture(
            builder => builder.Services.AddPasswordAuth<TestAppUser, TestDbContext>(o => o.Path = "/sign-in"),
            app => app.MapPasswordAuth<TestAppUser>());

        Assert.Contains("POST /sign-in/register", surface, StringComparison.Ordinal);
        Assert.Contains("POST /sign-in/login", surface, StringComparison.Ordinal);
        Assert.Contains("GET /sign-in/csrfToken", surface, StringComparison.Ordinal);
        Assert.DoesNotContain("/auth/", surface, StringComparison.Ordinal);
    }

    [Fact]
    public void Facade341_Source_MatchesCommittedSnapshots()
    {
        var cookie = Capture341(builder =>
        {
            builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(o =>
            {
                o.IdentityPath = "/identity";
                o.SignIn = AuthEndpointsSignIn.Cookie;
                o.PasskeyPath = "/account";
                o.RequireConfirmedAccount = true;
                o.Passkeys.Enabled = true;
                o.Passkeys.ServerDomain = "localhost";
                o.EmailConfirmation.ConfirmEmailRedirectUri = null;
                o.Jwt.Enabled = false;
                o.Jwt.Path = "/auth";
                o.EmailCode.Enabled = false;
                o.RequireEmailSenderInProduction = true;
                o.ConfigureIdentity = _ => { };
                o.ConfigurePasskeys = _ => { };
            });
            builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
        });
        Assert.Equal(ReadSnapshot("FacadeRouteSnapshotTests.Facade_Cookie_DefaultRouteSet.verified.txt"), cookie);

        var bearer = Capture341(builder =>
        {
            builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(
                AuthEndpointsSignIn.IdentityBearer,
                o =>
                {
                    o.IdentityPath = "/identity";
                    o.PasskeyPath = "/account";
                    o.Passkeys.Enabled = true;
                    o.Passkeys.ServerDomain = "localhost";
                    o.EmailCode.Enabled = false;
                    o.Jwt.Enabled = false;
                });
            builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
        });
        Assert.Equal(ReadSnapshot("FacadeRouteSnapshotTests.Facade_IdentityBearer_RouteSet.verified.txt"), bearer);

        var jwt = Capture341(builder =>
        {
            builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(
                AuthEndpointsSignIn.IdentityBearer,
                o =>
                {
                    o.Passkeys.ServerDomain = "localhost";
                    o.Jwt.Enabled = true;
                    o.Jwt.Path = "/auth";
                    o.Jwt.Configure = options => options.SigningOptions.SymmetricKey = SigningKey;
                    o.EmailCode.Enabled = false;
                });
            builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
        });
        Assert.Equal(ReadSnapshot("FacadeRouteSnapshotTests.Facade_IdentityBearer_WithJwt_RouteSet.verified.txt"), jwt);
    }

    [Fact]
    public void Facade341_RoleOverloads_StillCompile()
    {
        using var app = RouteSurface.Build(
            builder =>
            {
                builder.Services.AddDbContext<TestRolesDbContext>(o =>
                    o.UseInMemoryDatabase("facade341-roles-" + Guid.NewGuid().ToString("N")));
                builder.Services.AddAuthEndpoints<TestAppUser, IdentityRole, TestRolesDbContext>(o =>
                {
                    o.Passkeys.Enabled = false;
                    o.SignIn = AuthEndpointsSignIn.Cookie;
                });
                builder.Services.AddAuthEndpoints<TestAppUser, IdentityRole, TestRolesDbContext>(
                    AuthEndpointsSignIn.IdentityBearer,
                    o => o.Passkeys.Enabled = false);
            },
            app => app.MapAuthEndpoints<TestAppUser>());

        using var scope = app.Services.CreateScope();
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>());
        Assert.Equal(
            AuthEndpointsSignIn.IdentityBearer,
            scope.ServiceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthEndpointsOptions>>().Value.SignIn);
    }

    private static string Capture341(Action<WebApplicationBuilder> configure)
    {
        return Normalize(RouteSurface.Capture(
            configure,
            app =>
            {
                app.UseAuthEndpoints();
                app.MapAuthEndpoints<TestAppUser>();
            }));
    }

    private static string CaptureFacade(
        AuthEndpointsSession session,
        bool passkeys,
        RefreshTokenTransport? transport = null)
    {
        return RouteSurface.Capture(
            builder => AddFacade(builder.Services, session, passkeys, transport),
            app => app.MapPasswordAuth<TestAppUser>());
    }

    private static string CaptureBlocks(
        AuthEndpointsSession session,
        bool passkeys,
        RefreshTokenTransport? transport = null)
    {
        return RouteSurface.Capture(
            builder => AddBlocks(builder.Services, session, passkeys, transport),
            app => MapBlocks(app, session, passkeys));
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

    private static void AddFacade(
        IServiceCollection services,
        AuthEndpointsSession session,
        bool passkeys,
        RefreshTokenTransport? transport)
    {
        services.AddPasswordAuth<TestAppUser, TestDbContext>(o =>
        {
            o.Session = session;
            o.RequireConfirmedAccount = true;
            if (passkeys)
            {
                o.Passkeys.ServerDomain = "localhost";
            }

            if (session == AuthEndpointsSession.Jwt)
            {
                o.Jwt = jwt =>
                {
                    jwt.SigningOptions.SymmetricKey = SigningKey;
                    if (transport is not null)
                    {
                        jwt.RefreshTokenTransport = transport.Value;
                    }
                };
            }
        });
        services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
    }

    /// <summary>
    /// Documented building-block expansion of <c>AddPasswordAuth</c> / <c>MapPasswordAuth</c>.
    /// Keep this list aligned with the getting-started password facade page.
    /// </summary>
    private static void AddBlocks(
        IServiceCollection services,
        AuthEndpointsSession session,
        bool passkeys,
        RefreshTokenTransport? transport)
    {
        services.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>(identity =>
        {
            identity.SignIn.RequireConfirmedAccount = true;
        });
        services.AddPasswordSignUpEndpoints();
        services.AddPasswordSignInEndpoints();
        services.AddPasswordRecoveryEndpoints();
        services.AddAccountManagementEndpoints();

        if (session == AuthEndpointsSession.Jwt)
        {
            services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
            {
                jwt.SigningOptions.SymmetricKey = SigningKey;
                if (transport is not null)
                {
                    jwt.RefreshTokenTransport = transport.Value;
                }
            });
        }
        else
        {
            services.AddCookieSessionEndpoints();
        }

        if (passkeys)
        {
            services.AddPasskeyEndpoints<TestAppUser>();
            services.Configure<IdentityPasskeyOptions>(passkeysOptions => passkeysOptions.ServerDomain = "localhost");
        }

        services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
    }

    private static void MapBlocks(WebApplication app, AuthEndpointsSession session, bool passkeys)
    {
        var group = app.MapGroup("/auth");
        group.MapPasswordSignUpEndpoints<TestAppUser>();
        if (session == AuthEndpointsSession.Jwt)
        {
            group.MapJwtPasswordEndpoints<TestAppUser>();
        }
        else
        {
            group.MapPasswordSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
        }

        group.MapPasswordRecoveryEndpoints<TestAppUser>();
        if (session == AuthEndpointsSession.Jwt)
        {
            group.MapJwtSessionEndpoints<TestAppUser>();
        }
        else
        {
            group.MapCookieSessionEndpoints<TestAppUser>();
        }

        group.MapAccountManagementEndpoints<TestAppUser>();
        if (!passkeys)
        {
            return;
        }

        group.MapPasskeySignInEndpoints<TestAppUser>(session);
        group.MapPasskeyManagementEndpoints<TestAppUser>();
    }

    private static string ReadSnapshot(string fileName)
    {
        var path = RepoFile(Path.Combine("tests", "AuthEndpoints.Tests", "PublicApi", fileName));
        return Normalize(File.ReadAllText(path));
    }

    private static string RepoFile(string relative)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "AuthEndpoints.sln")))
            {
                return Path.Combine(dir.FullName, relative);
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException("Could not find AuthEndpoints.sln from the test output directory.");
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
