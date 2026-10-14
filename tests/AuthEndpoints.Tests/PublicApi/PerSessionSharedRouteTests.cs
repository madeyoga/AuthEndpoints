using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Tests.PublicApi;

public class PerSessionSharedRouteTests
{
    [Fact]
    public Task MapIdentityManagementApi_Matches341RouteTable()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.AddCookieAuthEndpoints();
            },
            app => app.MapGroup("/identity").MapIdentityManagementApi<TestAppUser>());
        return Verifier.Verify(surface);
    }

    [Fact]
    public Task MapCookieAuthEndpoints_Matches341RouteTable()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.AddCookieAuthEndpoints();
            },
            app => app.MapGroup("/identity").MapCookieAuthEndpoints<TestAppUser>());
        return Verifier.Verify(surface);
    }

    [Fact]
    public Task MapBearerAuthEndpoints_Matches341RouteTable()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.AddBearerAuthEndpoints();
            },
            app => app.MapGroup("/identity").MapBearerAuthEndpoints<TestAppUser>());
        return Verifier.Verify(surface);
    }

    [Fact]
    public Task MapJwtAuthEndpoints_Matches341RouteTable()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.AddAntiforgery();
                builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
                {
                    jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
                });
            },
            app => app.MapGroup("/auth").MapJwtAuthEndpoints<TestAppUser>());
        return Verifier.Verify(surface);
    }

    [Fact]
    public Task MapPasskeyEndpoints_Matches341RouteTable()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                AddIdentity(builder);
                builder.Services.AddPasskeyEndpoints<TestAppUser>();
            },
            app => app.MapGroup("/account").MapPasskeyEndpoints<TestAppUser>());
        return Verifier.Verify(surface);
    }

    [Fact]
    public void MapPasswordEndpoints_MatchesSignUpSignInAndRecovery()
    {
        var composite = RouteSurface.Capture(
            Identity,
            app => app.MapGroup("/identity").MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.Cookie));
        var pieces = RouteSurface.Capture(
            Identity,
            app =>
            {
                var group = app.MapGroup("/identity");
                group.MapPasswordSignUpEndpoints<TestAppUser>();
                group.MapPasswordSignInEndpoints<TestAppUser>(PasswordLoginMode.Cookie);
                group.MapPasswordRecoveryEndpoints<TestAppUser>();
            });

        Assert.Equal(composite, pieces);
    }

    [Fact]
    public void MapEmailCodeEndpoints_MatchesSendAndSignIn()
    {
        var composite = RouteSurface.Capture(
            EmailCode,
            app => app.MapGroup("/identity").MapEmailCodeEndpoints<TestAppUser>());
        var pieces = RouteSurface.Capture(
            EmailCode,
            app =>
            {
                var group = app.MapGroup("/identity");
                group.MapEmailCodeSendEndpoints<TestAppUser>();
                group.MapEmailCodeSignInEndpoints<TestAppUser>();
            });

        Assert.Equal(composite, pieces);
    }

    [Fact]
    public void EmailCodeMaps_Alone_OmitPasswordRoutes()
    {
        var routes = Routes(EmailCode, app =>
        {
            app.MapEmailCodeSendEndpoints<TestAppUser>();
            app.MapEmailCodeSignInEndpoints<TestAppUser>();
        });

        Assert.Equal(
            [
                "POST /emailCode/send",
                "POST /emailCode/verify",
            ],
            routes);
        Assert.DoesNotContain(routes, route => route.Contains("/register", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, route => route.Contains("/login", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, route => route.Contains("/forgotPassword", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, route => route.Contains("/resetPassword", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, route => route.Contains("/create", StringComparison.Ordinal));
    }

    [Fact]
    public void EmailCodeSession_MapsNoPasswordRoutes()
    {
        var routes = Routes(builder =>
        {
            EmailCode(builder);
            builder.Services.AddCookieSessionEndpoints();
            builder.Services.AddAccountManagementEndpoints();
        }, app =>
        {
            app.MapGroup("/web").MapSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
            app.MapSharedAuthEndpoints<TestAppUser>();
        });

        Assert.Contains("POST /emailCode/send", routes);
        Assert.Contains("POST /web/emailCode/verify", routes);
        Assert.Contains("POST /web/logout", routes);
        Assert.Contains("GET /web/csrfToken", routes);
        Assert.Contains("GET /confirmEmail", routes);
        Assert.DoesNotContain(routes, route => route.Contains("/register", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, route => route.Contains("/login", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, route => route.Contains("/forgotPassword", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, route => route.Contains("/resetPassword", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, route => route.Contains("/create", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, route => route.Contains("/passkeys", StringComparison.Ordinal));
    }

    [Fact]
    public void TwoSessionPrefixes_AndOneSharedMap_HaveNoDuplicateRouteNames()
    {
        using var app = RouteSurface.Build(builder =>
        {
            Identity(builder);
            builder.Services.AddPasswordEndpoints();
            builder.Services.AddCookieSessionEndpoints();
            builder.Services.AddAccountManagementEndpoints();
            builder.Services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>();
            builder.Services.AddPasskeyEndpoints<TestAppUser>();
            builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            });
        }, app =>
        {
            app.MapGroup("/web").MapSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
            app.MapGroup("/app").MapSignInEndpoints<TestAppUser>(AuthEndpointsSession.Jwt);
            app.MapSharedAuthEndpoints<TestAppUser>();
        });

        var endpoints = ((IEndpointRouteBuilder)app).DataSources.SelectMany(source => source.Endpoints).ToArray();
        var names = endpoints
            .Select(endpoint => endpoint.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName)
            .Where(name => !string.IsNullOrEmpty(name))
            .ToArray();
        Assert.Equal(names.Length, names.Distinct(StringComparer.Ordinal).Count());

        var keys = endpoints.Select(Format).ToArray();
        Assert.Equal(keys.Length, keys.Distinct(StringComparer.Ordinal).Count());

        Assert.Equal(1, keys.Count(key => key == "GET /confirmEmail"));
        Assert.Equal(1, keys.Count(key => key == "POST /register"));
        Assert.Equal(1, keys.Count(key => key == "POST /forgotPassword"));
        Assert.Equal(1, keys.Count(key => key == "POST /resetPassword"));
        Assert.Equal(1, keys.Count(key => key == "POST /emailCode/send"));
        Assert.Equal(1, keys.Count(key => key == "POST /passkeys/register/options"));
        Assert.Contains("POST /web/login", keys);
        Assert.Contains("POST /app/create", keys);
        Assert.Contains("POST /web/passkeys/register", keys);
        Assert.Contains("POST /app/passkeys/register", keys);
        Assert.Contains("POST /web/passkeys/login", keys);
        Assert.Contains("POST /app/passkeys/login", keys);
        Assert.Contains("POST /web/passkeys/requestOptions", keys);
        Assert.Contains("POST /app/passkeys/requestOptions", keys);
        Assert.DoesNotContain("POST /passkeys/requestOptions", keys);
        Assert.DoesNotContain("POST /app/login", keys);
        Assert.DoesNotContain("POST /web/create", keys);
        Assert.DoesNotContain("POST /web/passkeys/register/options", keys);
        Assert.DoesNotContain("POST /app/passkeys/register/options", keys);
        Assert.DoesNotContain("POST /web/register", keys);
        Assert.DoesNotContain("POST /app/register", keys);

        Assert.Equal(SignInCompleters.Cookie, Completer(Find(app, "POST /web/login")));
        Assert.Equal(SignInCompleters.Cookie, Completer(Find(app, "POST /web/emailCode/verify")));
        Assert.Equal(SignInCompleters.Cookie, Completer(Find(app, "POST /web/passkeys/login")));
        Assert.Equal(SignInCompleters.Cookie, Completer(Find(app, "POST /web/passkeys/register")));
        Assert.Equal(SignInCompleters.Jwt, Completer(Find(app, "POST /app/emailCode/verify")));
        Assert.Equal(SignInCompleters.Jwt, Completer(Find(app, "POST /app/passkeys/login")));
        Assert.Equal(SignInCompleters.Jwt, Completer(Find(app, "POST /app/passkeys/register")));

        var selections = endpoints
            .Select(endpoint => (Route: Format(endpoint), Name: endpoint.Metadata.GetMetadata<SignInCompleterSelection>()?.Name))
            .Where(item => item.Name is not null)
            .ToArray();
        Assert.Contains(selections, item => item.Route.Contains(" /web/", StringComparison.Ordinal));
        Assert.Contains(selections, item => item.Route.Contains(" /app/", StringComparison.Ordinal));
        Assert.All(selections, item =>
        {
            if (item.Route.Contains(" /web/", StringComparison.Ordinal))
            {
                Assert.Equal(SignInCompleters.Cookie, item.Name);
            }
            else if (item.Route.Contains(" /app/", StringComparison.Ordinal))
            {
                Assert.Equal(SignInCompleters.Jwt, item.Name);
            }
            else
            {
                Assert.Fail($"Shared route {item.Route} selected completer {item.Name}.");
            }
        });
    }

    [Fact]
    public void PasswordSignInMap_IsSetOnlyWhenLoginOrCreateIsMapped()
    {
        using (var signUp = RouteSurface.Build(Identity, app =>
        {
            app.MapPasswordSignUpEndpoints<TestAppUser>();
            app.MapPasswordRecoveryEndpoints<TestAppUser>();
        }))
        {
            Assert.False(PasswordSignInMap.IsMapped(signUp.Services));
        }

        using (var management = RouteSurface.Build(
            builder => builder.Services.AddCookieAuthEndpoints(),
            app => app.MapIdentityManagementApi<TestAppUser>()))
        {
            Assert.False(PasswordSignInMap.IsMapped(management.Services));
        }

        using (var login = RouteSurface.Build(
            builder => builder.Services.AddPasswordSignInEndpoints(),
            app => app.MapPasswordSignInEndpoints<TestAppUser>()))
        {
            Assert.True(PasswordSignInMap.IsMapped(login.Services));
        }

        using (var cookie = RouteSurface.Build(
            builder => builder.Services.AddCookieAuthEndpoints(),
            app => app.MapCookieAuthEndpoints<TestAppUser>()))
        {
            Assert.True(PasswordSignInMap.IsMapped(cookie.Services));
        }

        using (var jwt = RouteSurface.Build(builder =>
        {
            AddIdentity(builder);
            builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(options =>
            {
                options.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            });
        }, app => app.MapJwtPasswordEndpoints<TestAppUser>()))
        {
            Assert.True(PasswordSignInMap.IsMapped(jwt.Services));
        }
    }

    [Fact]
    public void MapPasswordSignInEndpoints_None_Throws()
    {
        using var app = RouteSurface.Build(Identity, _ => { });
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
            app.MapPasswordSignInEndpoints<TestAppUser>(PasswordLoginMode.None));
        Assert.Contains("POST /login", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NewMaps_ReturnConventionBuilders()
    {
        using var app = RouteSurface.Build(builder =>
        {
            Identity(builder);
            builder.Services.AddPasswordEndpoints();
            builder.Services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>();
            builder.Services.AddPasskeyEndpoints<TestAppUser>();
            builder.Services.AddCookieSessionEndpoints();
        }, app =>
        {
            IEndpointConventionBuilder signUp = app.MapPasswordSignUpEndpoints<TestAppUser>().WithTags("signup");
            IEndpointConventionBuilder signIn = app.MapGroup("/in").MapPasswordSignInEndpoints<TestAppUser>().WithTags("signin");
            IEndpointConventionBuilder recovery = app.MapPasswordRecoveryEndpoints<TestAppUser>().WithTags("recovery");
            IEndpointConventionBuilder send = app.MapEmailCodeSendEndpoints<TestAppUser>().WithTags("send");
            IEndpointConventionBuilder verify = app.MapGroup("/in").MapEmailCodeSignInEndpoints<TestAppUser>().WithTags("verify");
            IEndpointConventionBuilder passkeySignUp = app.MapPasskeySignUpEndpoints<TestAppUser>().WithTags("passkey-signup");
            IEndpointConventionBuilder options = app.MapPasskeyRegisterOptionsEndpoints<TestAppUser>().WithTags("passkey-options");
            IEndpointConventionBuilder shared = app.MapGroup("/shared").MapSharedAuthEndpoints<TestAppUser>().WithTags("shared");
            IEndpointConventionBuilder session = app.MapGroup("/web").MapSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie).WithTags("web");
            _ = signUp;
            _ = signIn;
            _ = recovery;
            _ = send;
            _ = verify;
            _ = passkeySignUp;
            _ = options;
            _ = shared;
            _ = session;
        });

        Assert.Contains("signup", Tags(Find(app, "POST /register")));
        Assert.Contains("signup", Tags(Find(app, "GET /confirmEmail")));
        Assert.Contains("signin", Tags(Find(app, "POST /in/login")));
        Assert.Contains("recovery", Tags(Find(app, "POST /forgotPassword")));
        Assert.Contains("send", Tags(Find(app, "POST /emailCode/send")));
        Assert.Contains("verify", Tags(Find(app, "POST /in/emailCode/verify")));
        Assert.Contains("passkey-signup", Tags(Find(app, "POST /passkeys/register")));
        Assert.Contains("passkey-options", Tags(Find(app, "POST /passkeys/register/options")));
        Assert.Contains("web", Tags(Find(app, "POST /web/login")));
        Assert.Contains("shared", Tags(Find(app, "POST /shared/resetPassword")));
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

    private static void Identity(WebApplicationBuilder builder)
    {
        AddIdentity(builder);
        builder.Services.AddPasswordEndpoints();
    }

    private static void EmailCode(WebApplicationBuilder builder)
    {
        AddIdentity(builder);
        builder.Services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>();
    }

    private static IReadOnlyList<string> Routes(Action<WebApplicationBuilder> configure, Action<WebApplication> map)
    {
        using var app = RouteSurface.Build(configure, map);
        return RouteSurface.ListRoutes(app);
    }

    private static string? Completer(Endpoint endpoint)
    {
        return endpoint.Metadata.GetMetadata<SignInCompleterSelection>()?.Name;
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

    private static IReadOnlyList<string> Tags(Endpoint endpoint)
    {
        return endpoint.Metadata.GetMetadata<ITagsMetadata>()?.Tags ?? [];
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
}
