using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests.PublicApi;

public class BuildingBlockRouteTests
{
    [Fact]
    public void MapPasswordEndpoints_Cookie_MapsRegisterLoginAndConfirmEmail()
    {
        var routes = MapIdentity(services => services.AddPasswordEndpoints(), app =>
        {
            app.MapGroup("/identity").MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.Cookie);
        });

        Assert.Equal(
            [
                "GET /identity/confirmEmail",
                "POST /identity/forgotPassword",
                "POST /identity/login",
                "POST /identity/register",
                "POST /identity/resendConfirmationEmail",
                "POST /identity/resetPassword",
            ],
            routes);
    }

    [Fact]
    public void MapPasswordEndpoints_IdentityBearer_MapsLogin()
    {
        var routes = MapIdentity(services => services.AddPasswordEndpoints(), app =>
        {
            app.MapGroup("/identity").MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.IdentityBearer);
        });

        Assert.Contains("POST /identity/login", routes);
        Assert.DoesNotContain("POST /identity/logout", routes);
        Assert.DoesNotContain("GET /identity/csrfToken", routes);
    }

    [Fact]
    public void MapPasswordEndpoints_None_OmitsLogin()
    {
        var routes = MapIdentity(services => services.AddPasswordEndpoints(), app =>
        {
            app.MapGroup("/identity").MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.None);
        });

        Assert.DoesNotContain("POST /identity/login", routes);
        Assert.Contains("POST /identity/register", routes);
        Assert.Contains("GET /identity/confirmEmail", routes);
    }

    [Fact]
    public void MapConfirmEmailEndpoints_MapsNamedConfirmAndResend()
    {
        using var app = BuildIdentity(services => services.AddAccountAbuseRateLimiting(), app =>
        {
            app.MapGroup("/identity").MapConfirmEmailEndpoints<TestAppUser>();
        });

        Assert.Equal(
            [
                "GET /identity/confirmEmail",
                "POST /identity/resendConfirmationEmail",
            ],
            RouteSurface.ListRoutes(app));

        var confirm = Find(app, "GET /identity/confirmEmail");
        var name = confirm.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName;
        Assert.Equal(AuthEndpointsEndpointNames.ConfirmEmail<TestAppUser>(), name);
        Assert.Equal("MapIdentityManagementApi-TestAppUser-confirmEmail", name);
    }

    [Fact]
    public void MapConfirmEmailEndpoints_ExplicitThenEnsure_MapsOneRoute()
    {
        var routes = MapIdentity(services =>
        {
            services.AddPasswordEndpoints();
            services.AddAccountManagementEndpoints();
        }, app =>
        {
            var group = app.MapGroup("/identity");
            group.MapConfirmEmailEndpoints<TestAppUser>("custom-confirm");
            group.MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.None, "custom-confirm");
            group.MapAccountManagementEndpoints<TestAppUser>("custom-confirm");
        });

        Assert.Equal(1, routes.Count(route => route == "GET /identity/confirmEmail"));
        Assert.Equal(1, routes.Count(route => route == "POST /identity/resendConfirmationEmail"));
    }

    [Fact]
    public void MapConfirmEmailEndpoints_TwoNames_MapBoth()
    {
        using var app = BuildIdentity(services => services.AddAccountAbuseRateLimiting(), app =>
        {
            var group = app.MapGroup("/identity");
            group.MapConfirmEmailEndpoints<TestAppUser>("first-confirm");
            group.MapConfirmEmailEndpoints<TestAppUser>("second-confirm");
        });

        var names = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(source => source.Endpoints)
            .Select(endpoint => endpoint.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName)
            .ToArray();
        Assert.Contains("first-confirm", names);
        Assert.Contains("second-confirm", names);
    }

    [Fact]
    public void MapCookieSessionEndpoints_MapsLogoutAndCsrf()
    {
        var routes = MapIdentity(services => services.AddCookieSessionEndpoints(), app =>
        {
            app.MapGroup("/identity").MapCookieSessionEndpoints<TestAppUser>();
        });

        Assert.Equal(
            [
                "GET /identity/csrfToken",
                "POST /identity/logout",
            ],
            routes);
    }

    [Fact]
    public void MapBearerSessionEndpoints_MapsRefreshAndLogout()
    {
        var routes = MapIdentity(services => services.AddBearerSessionEndpoints(), app =>
        {
            app.MapGroup("/identity").MapBearerSessionEndpoints<TestAppUser>();
        });

        Assert.Equal(
            [
                "POST /identity/logout",
                "POST /identity/refresh",
            ],
            routes);
    }

    [Fact]
    public void MapAccountManagementEndpoints_WithoutPasskeys_OmitsPasskeyOptions()
    {
        var routes = MapIdentity(services => services.AddAccountManagementEndpoints(), app =>
        {
            app.MapGroup("/identity").MapAccountManagementEndpoints<TestAppUser>();
        });

        Assert.Equal(
            [
                "GET /identity/confirmEmail",
                "GET /identity/manage/2fa",
                "GET /identity/manage/authMethods",
                "GET /identity/manage/info",
                "POST /identity/confirmIdentity",
                "POST /identity/manage/2fa",
                "POST /identity/manage/info",
                "POST /identity/resendConfirmationEmail",
            ],
            routes);
    }

    [Fact]
    public void MapAccountManagementEndpoints_WithPasskeys_MapsPasskeyOptions()
    {
        var routes = MapIdentity(services =>
        {
            services.AddAccountManagementEndpoints();
            services.AddPasskeyEndpoints<TestAppUser>();
        }, app =>
        {
            app.MapGroup("/identity").MapAccountManagementEndpoints<TestAppUser>();
        });

        Assert.Contains("POST /identity/confirmIdentity/passkeyOptions", routes);
        Assert.Equal(1, routes.Count(route => route == "POST /identity/confirmIdentity/passkeyOptions"));
    }

    [Fact]
    public void MapIdentityManagementApi_AlwaysIncludesPasskeyOptions()
    {
        var routes = MapIdentity(services => services.AddCookieAuthEndpoints(), app =>
        {
            app.MapGroup("/identity").MapIdentityManagementApi<TestAppUser>();
        });

        Assert.Contains("POST /identity/confirmIdentity/passkeyOptions", routes);
        Assert.DoesNotContain("POST /identity/login", routes);
        Assert.Equal(1, routes.Count(route => route == "GET /identity/confirmEmail"));
        Assert.Equal(1, routes.Count(route => route == "POST /identity/register"));
    }

    [Fact]
    public void ManagementPlusCookie_DoesNotDuplicateRegisterOrLogin()
    {
        var routes = MapIdentity(services => services.AddCookieAuthEndpoints(), app =>
        {
            var group = app.MapGroup("/identity");
            group.MapIdentityManagementApi<TestAppUser>();
            group.MapCookieAuthEndpoints<TestAppUser>();
        });

        Assert.Equal(1, routes.Count(route => route == "POST /identity/register"));
        Assert.Equal(1, routes.Count(route => route == "POST /identity/login"));
        Assert.Equal(1, routes.Count(route => route == "POST /identity/logout"));
        Assert.Equal(1, routes.Count(route => route == "GET /identity/csrfToken"));
        Assert.Equal(1, routes.Count(route => route == "GET /identity/confirmEmail"));
    }

    [Fact]
    public void MapJwtPasswordAndSession_SplitCreateFromSession()
    {
        var password = MapIdentity(services =>
        {
            services.AddAntiforgery();
            services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            });
        }, app =>
        {
            app.MapGroup("/auth").MapJwtPasswordEndpoints<TestAppUser>();
        });
        Assert.Equal(["POST /auth/create"], password);

        var session = MapIdentity(services =>
        {
            services.AddAntiforgery();
            services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            });
        }, app =>
        {
            app.MapGroup("/auth").MapJwtSessionEndpoints<TestAppUser>();
        });
        Assert.Equal(
            [
                "GET /auth/csrfToken",
                "GET /auth/verify",
                "POST /auth/logout",
                "POST /auth/refresh",
            ],
            session);
    }

    [Fact]
    public void MapPasskeySignInAndManagement_SplitRoutes()
    {
        var signIn = MapIdentity(services => services.AddPasskeyEndpoints<TestAppUser>(), app =>
        {
            app.MapGroup("/account").MapPasskeySignInEndpoints<TestAppUser>();
        });
        Assert.Equal(
            [
                "GET /account/confirmEmail",
                "POST /account/passkeys/login",
                "POST /account/passkeys/register",
                "POST /account/passkeys/register/options",
                "POST /account/passkeys/requestOptions",
                "POST /account/resendConfirmationEmail",
            ],
            signIn);

        var management = MapIdentity(services => services.AddPasskeyEndpoints<TestAppUser>(), app =>
        {
            app.MapGroup("/account").MapPasskeyManagementEndpoints<TestAppUser>();
        });
        Assert.Equal(
            [
                "DELETE /account/passkeys/{credentialIdUrl}",
                "GET /account/passkeys/",
                "PATCH /account/passkeys/",
                "POST /account/passkeys/",
                "POST /account/passkeys/creationOptions",
            ],
            management);
    }

    [Fact]
    public void MapPasskeyEndpoints_DoesNotAutoMapConfirmEmail()
    {
        var routes = MapIdentity(services => services.AddPasskeyEndpoints<TestAppUser>(), app =>
        {
            app.MapGroup("/account").MapPasskeyEndpoints<TestAppUser>();
        });

        Assert.DoesNotContain("GET /account/confirmEmail", routes);
        Assert.Contains("POST /account/passkeys/login", routes);
        Assert.Contains("POST /account/passkeys/creationOptions", routes);
    }

    [Fact]
    public void CookieLogout_UsesDefaultAuthorization_ManagementUsesRegisteredSchemes()
    {
        using var app = BuildIdentity(services => services.AddCookieAuthEndpoints(), app =>
        {
            var group = app.MapGroup("/identity");
            group.MapIdentityManagementApi<TestAppUser>();
            group.MapCookieAuthEndpoints<TestAppUser>();
        });

        var logout = Find(app, "POST /identity/logout");
        var logoutAuth = logout.Metadata.GetOrderedMetadata<IAuthorizeData>().Single();
        Assert.True(string.IsNullOrEmpty(logoutAuth.AuthenticationSchemes));

        var info = Find(app, "GET /identity/manage/info");
        var infoAuth = info.Metadata.GetOrderedMetadata<IAuthorizeData>().Single();
        Assert.Contains("Identity.Application", infoAuth.AuthenticationSchemes, StringComparison.Ordinal);
        Assert.Contains("Identity.Bearer", infoAuth.AuthenticationSchemes, StringComparison.Ordinal);
        Assert.DoesNotContain("Bearer", infoAuth.AuthenticationSchemes!.Split(','), StringComparer.Ordinal);

        Assert.Equal(
            AuthEndpointsConstants.AccountAbusePolicy,
            Find(app, "POST /identity/register").Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName);
        Assert.Equal(
            AuthEndpointsConstants.LoginPolicy,
            Find(app, "POST /identity/login").Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName);
        Assert.Equal(
            AuthEndpointsConstants.ConfirmIdentityPolicy,
            Find(app, "POST /identity/confirmIdentity").Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName);
    }

    [Theory]
    [InlineData("MapPasswordEndpoints")]
    [InlineData("MapCookieSessionEndpoints")]
    [InlineData("MapBearerSessionEndpoints")]
    [InlineData("MapAccountManagementEndpoints")]
    [InlineData("MapConfirmEmailEndpoints")]
    [InlineData("MapJwtPasswordEndpoints")]
    [InlineData("MapJwtSessionEndpoints")]
    [InlineData("MapPasskeySignInEndpoints")]
    [InlineData("MapPasskeyManagementEndpoints")]
    public void Map_WithoutMatchingAdd_LogsWarningAndStillMaps(string mapMethod)
    {
        var logs = new WarningLog();
        using var app = BuildIdentity(_ => { }, app =>
        {
            var identity = app.MapGroup("/identity");
            var auth = app.MapGroup("/auth");
            var account = app.MapGroup("/account");
            switch (mapMethod)
            {
                case "MapPasswordEndpoints":
                    identity.MapPasswordEndpoints<TestAppUser>();
                    break;
                case "MapCookieSessionEndpoints":
                    identity.MapCookieSessionEndpoints<TestAppUser>();
                    break;
                case "MapBearerSessionEndpoints":
                    identity.MapBearerSessionEndpoints<TestAppUser>();
                    break;
                case "MapAccountManagementEndpoints":
                    identity.MapAccountManagementEndpoints<TestAppUser>();
                    break;
                case "MapConfirmEmailEndpoints":
                    identity.MapConfirmEmailEndpoints<TestAppUser>();
                    break;
                case "MapJwtPasswordEndpoints":
                    auth.MapJwtPasswordEndpoints<TestAppUser>();
                    break;
                case "MapJwtSessionEndpoints":
                    auth.MapJwtSessionEndpoints<TestAppUser>();
                    break;
                case "MapPasskeySignInEndpoints":
                    account.MapPasskeySignInEndpoints<TestAppUser>();
                    break;
                case "MapPasskeyManagementEndpoints":
                    account.MapPasskeyManagementEndpoints<TestAppUser>();
                    break;
            }
        }, logs);

        Assert.Contains(logs.Messages, message => message.Contains(mapMethod, StringComparison.Ordinal));
    }

    [Fact]
    public void Map_WithMatchingAdd_DoesNotLogMissingAddWarning()
    {
        var logs = new WarningLog();
        using var app = BuildIdentity(services =>
        {
            services.AddPasswordEndpoints();
            services.AddCookieSessionEndpoints();
            services.AddBearerSessionEndpoints();
            services.AddAccountManagementEndpoints();
            services.AddPasskeyEndpoints<TestAppUser>();
            services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            });
        }, app =>
        {
            var identity = app.MapGroup("/identity");
            identity.MapPasswordEndpoints<TestAppUser>();
            identity.MapCookieSessionEndpoints<TestAppUser>();
            identity.MapBearerSessionEndpoints<TestAppUser>();
            identity.MapAccountManagementEndpoints<TestAppUser>();
            identity.MapConfirmEmailEndpoints<TestAppUser>();
            app.MapGroup("/auth").MapJwtAuthEndpoints<TestAppUser>();
            app.MapGroup("/account").MapPasskeyEndpoints<TestAppUser>();
            app.MapGroup("/account").MapPasskeySignInEndpoints<TestAppUser>();
        }, logs);

        Assert.DoesNotContain(logs.Messages, message => message.Contains("was not called before", StringComparison.Ordinal));
    }

    [Fact]
    public void AddMethods_AreIdempotent()
    {
        AssertIdempotent(services => services.AddPasswordEndpoints());
        AssertIdempotent(services => services.AddCookieSessionEndpoints());
        AssertIdempotent(services => services.AddBearerSessionEndpoints());
        AssertIdempotent(services => services.AddAccountManagementEndpoints());
        AssertIdempotent(services => services.AddLoginRateLimiting());
        AssertIdempotent(services => services.AddAccountAbuseRateLimiting());
        AssertIdempotent(services => services.AddConfirmIdentityRateLimiting());
        AssertIdempotent(services => services.AddPasskeyEndpoints());

        var identity = new ServiceCollection();
        identity.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase("identity-once"));
        identity.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>();
        var identityCount = identity.Count;
        identity.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>(o => o.Password.RequiredLength = 8);
        Assert.Equal(identityCount, identity.Count);
    }

    [Fact]
    public void FacadePlusExplicitAdd_DoesNotDuplicatePolicies()
    {
        var services = new ServiceCollection();
        services.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase("facade-plus-add"));
        services.AddAuthEndpoints<TestAppUser, TestDbContext>(o =>
        {
            o.Passkeys.ServerDomain = "localhost";
            o.Jwt.Enabled = true;
            o.Jwt.Configure = jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            };
        });
        services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
        services.AddPasswordEndpoints();
        services.AddCookieSessionEndpoints();
        services.AddBearerSessionEndpoints();
        services.AddAccountManagementEndpoints();
        services.AddPasskeyEndpoints<TestAppUser>();
        services.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>();
        services.AddBearerAuthEndpoints();

        using var provider = services.BuildServiceProvider();
        var policies = provider.GetRequiredService<IOptions<RateLimiterOptions>>().Value;
        Assert.NotNull(policies);
        Assert.NotNull(provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value);
    }

    [Fact]
    public void RequireAuthEndpointsUser_MatchesManagementAuthorization()
    {
        using var app = BuildIdentity(services => services.AddCookieAuthEndpoints(), app =>
        {
            app.MapGet("/user", () => Results.Ok()).RequireAuthEndpointsUser();
        });

        var endpoint = Find(app, "GET /user");
        var auth = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>().Single();
        var expected = ManagementAuthorization.CreateAuthorizeAttribute(app);
        Assert.Equal(expected.AuthenticationSchemes, auth.AuthenticationSchemes);
        Assert.Contains(IdentityConstants.ApplicationScheme, auth.AuthenticationSchemes, StringComparison.Ordinal);
        Assert.Contains(IdentityConstants.BearerScheme, auth.AuthenticationSchemes, StringComparison.Ordinal);
    }

    private static IReadOnlyList<string> MapIdentity(
        Action<IServiceCollection> configure,
        Action<WebApplication> map)
    {
        using var app = BuildIdentity(configure, map);
        return RouteSurface.ListRoutes(app);
    }

    private static WebApplication BuildIdentity(
        Action<IServiceCollection> configure,
        Action<WebApplication> map,
        WarningLog? logs = null)
    {
        return RouteSurface.Build(builder =>
        {
            if (logs is not null)
            {
                builder.Logging.AddProvider(logs);
                builder.Logging.SetMinimumLevel(LogLevel.Warning);
            }

            builder.Services
                .AddIdentityApiEndpoints<TestAppUser>(options =>
                {
                    options.SignIn.RequireConfirmedAccount = true;
                    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                })
                .AddEntityFrameworkStores<TestDbContext>()
                .AddDefaultTokenProviders();
            configure(builder.Services);
        }, map);
    }

    private static Endpoint Find(WebApplication app, string route)
    {
        var matches = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(source => source.Endpoints)
            .Where(endpoint => Format(endpoint) == route)
            .ToArray();
        Assert.Single(matches);
        return matches[0];
    }

    private static string Format(Endpoint endpoint)
    {
        var methods = endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods;
        var method = methods is { Count: > 0 }
            ? string.Join(",", methods.OrderBy(name => name, StringComparer.Ordinal))
            : "*";
        var raw = endpoint is RouteEndpoint route
            ? route.RoutePattern.RawText ?? ""
            : "";
        return method + " " + raw;
    }

    private static void AssertIdempotent(Action<IServiceCollection> add)
    {
        var services = new ServiceCollection();
        add(services);
        var before = services.Select(Describe).ToArray();
        add(services);
        var added = services.Select(Describe).Skip(before.Length).ToArray();
        Assert.True(added.Length == 0, "Second call added: " + string.Join(", ", added));
    }

    private static string Describe(ServiceDescriptor descriptor)
    {
        return descriptor.ServiceType.FullName + " -> " + (descriptor.ImplementationType?.FullName ?? descriptor.ImplementationInstance?.GetType().FullName ?? "factory");
    }

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
