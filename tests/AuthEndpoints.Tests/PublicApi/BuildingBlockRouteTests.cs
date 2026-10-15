using System.Net;
using System.Net.Http;
using AuthEndpoints;
using AuthEndpoints.EmailCode;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
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
                "POST /identity/manage/password",
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
    public async Task AddAccountManagementEndpoints_DoesNotRegisterEmailCodeConfirmPolicy()
    {
        await using var management = RouteSurface.Build(
            builder => builder.Services.AddAccountManagementEndpoints(),
            app =>
            {
                app.UseRateLimiter();
                app.MapPost("/probe", () => Results.Ok())
                    .RequireRateLimiting(AuthEndpointsConstants.ConfirmIdentityEmailCodePolicy);
            });
        await management.StartAsync();
        using (var client = management.GetTestClient())
        {
            var missing = await client.PostAsync("/probe", new StringContent(string.Empty));
            var body = await missing.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.InternalServerError, missing.StatusCode);
            Assert.Contains(AuthEndpointsConstants.ConfirmIdentityEmailCodePolicy, body, StringComparison.Ordinal);
        }

        await using var emailCode = RouteSurface.Build(
            builder =>
            {
                builder.Services
                    .AddIdentityApiEndpoints<TestAppUser>(options =>
                    {
                        options.SignIn.RequireConfirmedAccount = true;
                        options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                    })
                    .AddEntityFrameworkStores<TestDbContext>()
                    .AddDefaultTokenProviders();
                builder.Services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>();
            },
            app =>
            {
                app.UseRateLimiter();
                app.MapPost("/probe", () => Results.Ok())
                    .RequireRateLimiting(AuthEndpointsConstants.ConfirmIdentityEmailCodePolicy);
            });
        await emailCode.StartAsync();
        using var allowed = emailCode.GetTestClient();
        Assert.Equal(HttpStatusCode.OK, (await allowed.PostAsync("/probe", new StringContent(string.Empty))).StatusCode);
    }

    [Fact]
    public void MapAccountManagementEndpoints_WithEmailCode_MapsReAuthSend()
    {
        using var app = BuildIdentity(services =>
        {
            services.AddAccountManagementEndpoints();
            services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>();
        }, mapped =>
        {
            mapped.MapGroup("/identity").MapAccountManagementEndpoints<TestAppUser>();
        });

        var send = Find(app, "POST /identity/confirmIdentity/emailCode/send");
        Assert.Equal(
            AuthEndpointsConstants.ConfirmIdentityEmailCodePolicy,
            send.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName);
        Assert.NotNull(send.Metadata.GetMetadata<AuthEndpointsAntiforgeryMetadata>());
    }

    [Fact]
    public void MapReAuthEndpoints_MapsEmailCodeSendOnlyWhenTheStoreIsRegistered()
    {
        var without = MapIdentity(services => services.AddAccountManagementEndpoints(), app =>
        {
            app.MapGroup("/identity").MapReAuthEndpoints<TestAppUser>(requireAntiforgery: false);
        });
        Assert.DoesNotContain("POST /identity/confirmIdentity/emailCode/send", without);

        using var app = BuildIdentity(services =>
        {
            services.AddAccountManagementEndpoints();
            services.AddEmailCodeEndpoints<TestAppUser, TestDbContext>();
        }, mapped =>
        {
            mapped.MapGroup("/identity").MapReAuthEndpoints<TestAppUser>(requireAntiforgery: true);
        });

        var send = Find(app, "POST /identity/confirmIdentity/emailCode/send");
        Assert.Equal(
            AuthEndpointsConstants.ConfirmIdentityEmailCodePolicy,
            send.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName);
        Assert.NotNull(send.Metadata.GetMetadata<AuthEndpointsAntiforgeryMetadata>());
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
    [InlineData("MapPasswordEndpoints", "AddPasswordEndpoints", "MapPasswordEndpoints")]
    [InlineData("MapPasswordSignUpEndpoints", "AddPasswordSignUpEndpoints", "MapPasswordSignUpEndpoints")]
    [InlineData("MapPasswordSignInEndpoints", "AddPasswordSignInEndpoints", "MapPasswordSignInEndpoints")]
    [InlineData("MapPasswordRecoveryEndpoints", "AddPasswordRecoveryEndpoints", "MapPasswordRecoveryEndpoints")]
    [InlineData("MapCookieSessionEndpoints", "AddCookieSessionEndpoints", "MapCookieSessionEndpoints")]
    [InlineData("MapBearerSessionEndpoints", "AddBearerSessionEndpoints", "MapBearerSessionEndpoints")]
    [InlineData("MapCookieAuthEndpoints", "AddPasswordEndpoints", "MapCookieAuthEndpoints")]
    [InlineData("MapBearerAuthEndpoints", "AddPasswordEndpoints", "MapBearerAuthEndpoints")]
    [InlineData("MapIdentityManagementApi", "AddPasswordEndpoints", "MapPasswordEndpoints")]
    [InlineData("MapAccountManagementEndpoints", "AddAccountManagementEndpoints", "MapAccountManagementEndpoints")]
    [InlineData("MapConfirmEmailEndpoints", "AddAccountAbuseRateLimiting", "MapConfirmEmailEndpoints")]
    [InlineData("MapJwtPasswordEndpoints", "AddJwtEndpoints", "MapJwtPasswordEndpoints")]
    [InlineData("MapJwtSessionEndpoints", "AddJwtEndpoints", "MapJwtSessionEndpoints")]
    [InlineData("MapJwtAuthEndpoints", "AddJwtEndpoints", "MapJwtPasswordEndpoints")]
    [InlineData("MapPasskeySignInEndpoints", "AddPasskeySignInEndpoints", "MapPasskeySignInEndpoints")]
    [InlineData("MapPasskeyManagementEndpoints", "AddPasskeyManagementEndpoints", "MapPasskeyManagementEndpoints")]
    [InlineData("MapPasskeySignUpEndpoints", "AddPasskeySignUpEndpoints", "MapPasskeySignUpEndpoints")]
    [InlineData("MapPasskeyRegisterOptionsEndpoints", "AddPasskeyRegisterOptionsEndpoints", "MapPasskeyRegisterOptionsEndpoints")]
    [InlineData("MapPasskeyEndpoints", "AddPasskeyEndpoints", "MapPasskeyEndpoints")]
    [InlineData("MapEmailCodeEndpoints", "AddEmailCodeEndpoints", "MapEmailCodeEndpoints")]
    [InlineData("MapEmailCodeSendEndpoints", "AddEmailCodeSendEndpoints", "MapEmailCodeSendEndpoints")]
    [InlineData("MapEmailCodeSignInEndpoints", "AddEmailCodeSignInEndpoints", "MapEmailCodeSignInEndpoints")]
    [InlineData("MapExternalAuthEndpoints", "AddExternalAuthEndpoints", "MapExternalAuthEndpoints")]
    [InlineData("MapExternalAccountEndpoints", "AddExternalAuthEndpoints", "MapExternalAccountEndpoints")]
    [InlineData("MapReAuthEndpoints", "AddReAuthScheme", "MapReAuthEndpoints")]
    [InlineData("MapSignInEndpoints", "AddCookieSessionEndpoints", "MapCookieSessionEndpoints")]
    [InlineData("MapSharedAuthEndpoints", "AddAccountAbuseRateLimiting", "MapConfirmEmailEndpoints")]
    [InlineData("MapAuthEndpoints", "AddAuthEndpoints", "MapAuthEndpoints")]
    [InlineData("MapPasswordAuth", "AddPasswordAuth", "MapPasswordAuth")]
    public void Map_WithoutMatchingAdd_ThrowsNamedFix(string mapMethod, string addMethod, string namedMap)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => BuildIdentity(_ => { }, app =>
        {
            var identity = app.MapGroup("/identity");
            var auth = app.MapGroup("/auth");
            var account = app.MapGroup("/account");
            switch (mapMethod)
            {
                case "MapPasswordEndpoints":
                    identity.MapPasswordEndpoints<TestAppUser>();
                    break;
                case "MapPasswordSignUpEndpoints":
                    identity.MapPasswordSignUpEndpoints<TestAppUser>();
                    break;
                case "MapPasswordSignInEndpoints":
                    identity.MapPasswordSignInEndpoints<TestAppUser>();
                    break;
                case "MapPasswordRecoveryEndpoints":
                    identity.MapPasswordRecoveryEndpoints<TestAppUser>();
                    break;
                case "MapCookieSessionEndpoints":
                    identity.MapCookieSessionEndpoints<TestAppUser>();
                    break;
                case "MapBearerSessionEndpoints":
                    identity.MapBearerSessionEndpoints<TestAppUser>();
                    break;
                case "MapCookieAuthEndpoints":
                    identity.MapCookieAuthEndpoints<TestAppUser>();
                    break;
                case "MapBearerAuthEndpoints":
                    identity.MapBearerAuthEndpoints<TestAppUser>();
                    break;
                case "MapIdentityManagementApi":
                    identity.MapIdentityManagementApi<TestAppUser>();
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
                case "MapJwtAuthEndpoints":
                    auth.MapJwtAuthEndpoints<TestAppUser>();
                    break;
                case "MapPasskeySignInEndpoints":
                    account.MapPasskeySignInEndpoints<TestAppUser>();
                    break;
                case "MapPasskeyManagementEndpoints":
                    account.MapPasskeyManagementEndpoints<TestAppUser>();
                    break;
                case "MapPasskeyEndpoints":
                    account.MapPasskeyEndpoints<TestAppUser>();
                    break;
                case "MapExternalAuthEndpoints":
                    app.MapExternalAuthEndpoints<TestAppUser>();
                    break;
                case "MapExternalAccountEndpoints":
                    app.MapExternalAccountEndpoints<TestAppUser>();
                    break;
                case "MapPasskeySignUpEndpoints":
                    account.MapPasskeySignUpEndpoints<TestAppUser>();
                    break;
                case "MapPasskeyRegisterOptionsEndpoints":
                    account.MapPasskeyRegisterOptionsEndpoints<TestAppUser>();
                    break;
                case "MapEmailCodeEndpoints":
                    identity.MapEmailCodeEndpoints<TestAppUser>();
                    break;
                case "MapEmailCodeSendEndpoints":
                    identity.MapEmailCodeSendEndpoints<TestAppUser>();
                    break;
                case "MapEmailCodeSignInEndpoints":
                    identity.MapEmailCodeSignInEndpoints<TestAppUser>();
                    break;
                case "MapReAuthEndpoints":
                    identity.MapReAuthEndpoints<TestAppUser>();
                    break;
                case "MapSignInEndpoints":
                    app.MapSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
                    break;
                case "MapSharedAuthEndpoints":
                    app.MapSharedAuthEndpoints<TestAppUser>();
                    break;
                case "MapAuthEndpoints":
                    app.MapAuthEndpoints<TestAppUser>();
                    break;
                case "MapPasswordAuth":
                    app.MapPasswordAuth<TestAppUser>();
                    break;
            }
        }));

        Assert.Contains(addMethod, ex.Message, StringComparison.Ordinal);
        Assert.Contains(namedMap, ex.Message, StringComparison.Ordinal);
        Assert.Contains("before", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MapSignInEndpoints_WithNoSignInModule_LogsWarning()
    {
        var logs = new WarningLog();
        using var app = BuildIdentity(services => services.AddCookieSessionEndpoints(), app =>
        {
            app.MapGroup("/web").MapSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
        }, logs);

        _ = RouteSurface.ListRoutes(app);
        Assert.Contains(
            logs.Messages,
            message => message.Contains(
                "MapSignInEndpoints mapped no sign-in method.",
                StringComparison.Ordinal));
    }

    [Fact]
    public void PasskeySignInAndManagementAdds_MatchTheirMaps()
    {
        var signInLogs = new WarningLog();
        using var signIn = BuildIdentity(services =>
        {
            services.AddPasskeySignInEndpoints<TestAppUser>();
            services.AddCookieSessionEndpoints();
        }, app =>
        {
            app.MapGroup("/web").MapSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
        }, signInLogs);

        var signInRoutes = RouteSurface.ListRoutes(signIn);
        Assert.Contains("POST /web/passkeys/requestOptions", signInRoutes);
        Assert.Contains("POST /web/passkeys/login", signInRoutes);
        Assert.DoesNotContain("POST /web/passkeys/register", signInRoutes);
        Assert.DoesNotContain(signInRoutes, route => route.Contains("register/options", StringComparison.Ordinal));
        Assert.Equal(
            SignInCompleters.Cookie,
            Find(signIn, "POST /web/passkeys/login").Metadata.GetMetadata<SignInCompleterSelection>()?.Name);
        Assert.DoesNotContain(signInLogs.Messages, message => message.Contains("was not called before", StringComparison.Ordinal));
        Assert.DoesNotContain(signInLogs.Messages, message => message.Contains("mapped no sign-in method", StringComparison.Ordinal));

        var legacyLogs = new WarningLog();
        using var legacy = BuildIdentity(services => services.AddPasskeySignInEndpoints<TestAppUser>(), app =>
        {
            app.MapPasskeySignInEndpoints<TestAppUser>();
        }, legacyLogs);
        _ = RouteSurface.ListRoutes(legacy);
        Assert.DoesNotContain(legacyLogs.Messages, message => message.Contains("was not called before", StringComparison.Ordinal));

        var managementLogs = new WarningLog();
        using var management = BuildIdentity(services => services.AddPasskeyManagementEndpoints(), app =>
        {
            app.MapPasskeyManagementEndpoints<TestAppUser>();
        }, managementLogs);

        var managementRoutes = RouteSurface.ListRoutes(management);
        Assert.Contains("POST /passkeys/creationOptions", managementRoutes);
        Assert.Contains("GET /passkeys/", managementRoutes);
        Assert.DoesNotContain("POST /passkeys/login", managementRoutes);
        Assert.DoesNotContain(managementLogs.Messages, message => message.Contains("was not called before", StringComparison.Ordinal));
    }

    [Fact]
    public void CookieAndBearerSessions_OnTheSamePrefix_WarnAboutLogout()
    {
        var logs = new WarningLog();
        using var app = BuildIdentity(services =>
        {
            services.AddCookieSessionEndpoints();
            services.AddBearerSessionEndpoints();
        }, app =>
        {
            var identity = app.MapGroup("/identity");
            identity.MapCookieSessionEndpoints<TestAppUser>();
            identity.MapBearerSessionEndpoints<TestAppUser>();
        }, logs);

        _ = RouteSurface.ListRoutes(app);
        Assert.Contains(
            logs.Messages,
            message => message.Contains("MapCookieSessionEndpoints and MapBearerSessionEndpoints both map POST /identity/logout.", StringComparison.Ordinal));
    }

    [Fact]
    public void PasswordCookieMode_WithCookieAuth_WarnsAboutLogin()
    {
        var logs = new WarningLog();
        using var app = BuildIdentity(services => services.AddCookieAuthEndpoints(), app =>
        {
            var identity = app.MapGroup("/identity");
            identity.MapPasswordEndpoints<TestAppUser>(PasswordLoginMode.Cookie);
            identity.MapCookieAuthEndpoints<TestAppUser>();
        }, logs);

        _ = RouteSurface.ListRoutes(app);
        Assert.Contains(
            logs.Messages,
            message => message.Contains("MapPasswordEndpoints and MapCookieAuthEndpoints both map POST /identity/login.", StringComparison.Ordinal));
    }

    [Fact]
    public void MapAccountManagementEndpoints_WithTags_ReachesConfirmAndResend()
    {
        using var app = BuildIdentity(services => services.AddAccountManagementEndpoints(), app =>
        {
            app.MapGroup("/identity").MapAccountManagementEndpoints<TestAppUser>().WithTags("account");
        });

        Assert.Contains("account", Tags(Find(app, "GET /identity/confirmEmail")));
        Assert.Contains("account", Tags(Find(app, "POST /identity/resendConfirmationEmail")));
    }

    [Fact]
    public void MapPasskeySignInEndpoints_WithTags_ReachesConfirmAndResend()
    {
        using var app = BuildIdentity(services => services.AddPasskeyEndpoints<TestAppUser>(), app =>
        {
            app.MapGroup("/account").MapPasskeySignInEndpoints<TestAppUser>().WithTags("passkey");
        });

        Assert.Contains("passkey", Tags(Find(app, "GET /account/confirmEmail")));
        Assert.Contains("passkey", Tags(Find(app, "POST /account/resendConfirmationEmail")));
    }

    [Fact]
    public void MapConfirmEmailEndpoints_TakenName_WithTagsDoesNotReachExistingRoute()
    {
        using var app = BuildIdentity(services => services.AddAccountAbuseRateLimiting(), app =>
        {
            var group = app.MapGroup("/identity");
            group.MapConfirmEmailEndpoints<TestAppUser>();
            group.MapConfirmEmailEndpoints<TestAppUser>().WithTags("late");
        });

        Assert.Equal(1, RouteSurface.ListRoutes(app).Count(route => route == "GET /identity/confirmEmail"));
        Assert.DoesNotContain("late", Tags(Find(app, "GET /identity/confirmEmail")));
        Assert.DoesNotContain("late", Tags(Find(app, "POST /identity/resendConfirmationEmail")));
    }

    [Fact]
    public void Capture_IncludesNameAuthAntiforgeryAndRateLimit()
    {
        var surface = RouteSurface.Capture(
            builder => builder.Services.AddPasswordEndpoints(),
            app => app.MapGroup("/identity").MapPasswordEndpoints<TestAppUser>());

        Assert.Contains(
            "POST /identity/login name=(none) auth=(none) antiforgery=false rateLimit=AuthEndpoints.Login",
            surface,
            StringComparison.Ordinal);
        Assert.Contains(
            "GET /identity/confirmEmail name=MapIdentityManagementApi-TestAppUser-confirmEmail auth=(none) antiforgery=false rateLimit=(none)",
            surface,
            StringComparison.Ordinal);
        Assert.Contains(
            "POST /identity/resendConfirmationEmail name=(none) auth=(default) antiforgery=true rateLimit=AuthEndpoints.AccountAbuse",
            surface,
            StringComparison.Ordinal);
    }

    [Fact]
    public void AddMethods_AreIdempotent()
    {
        AssertIdempotent(services => services.AddPasswordEndpoints());
        AssertIdempotent(services => services.AddPasswordSignUpEndpoints());
        AssertIdempotent(services => services.AddPasswordSignInEndpoints());
        AssertIdempotent(services => services.AddPasswordRecoveryEndpoints());
        AssertIdempotent(services => services.AddCookieSessionEndpoints());
        AssertIdempotent(services => services.AddBearerSessionEndpoints());
        AssertIdempotent(services => services.AddAccountManagementEndpoints());
        AssertIdempotent(services => services.AddEmailCodeSendEndpoints<TestAppUser, TestDbContext>());
        AssertIdempotent(services => services.AddEmailCodeSignInEndpoints<TestAppUser, TestDbContext>());
        AssertIdempotent(services => services.AddPasskeySignUpEndpoints());
        AssertIdempotent(services => services.AddPasskeySignInEndpoints());
        AssertIdempotent(services => services.AddPasskeyRegisterOptionsEndpoints());
        AssertIdempotent(services => services.AddPasskeyManagementEndpoints());
        AssertIdempotent(services => services.AddLoginRateLimiting());
        AssertIdempotent(services => services.AddAccountAbuseRateLimiting());
        AssertIdempotent(services => services.AddConfirmIdentityRateLimiting());
        AssertIdempotent(services => services.AddPasskeyEndpoints());

        var identity = new ServiceCollection();
        identity.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase("identity-once"));
        identity.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>();
        var identityCount = identity.Count;
        identity.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>();
        Assert.Equal(identityCount, identity.Count);
        identity.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>(o => o.Password.RequiredLength = 8);
        using var provider = identity.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<IdentityOptions>>().Value;
        Assert.Equal(8, options.Password.RequiredLength);
        Assert.True(options.SignIn.RequireConfirmedAccount);
    }

    [Fact]
    public void SecondFacadeCall_AppliesConfirmedAccountAndPasswordOptions()
    {
        var services = new ServiceCollection();
        services.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase("identity-second-facade"));
        services.AddAuthEndpointsIdentity<TestAppUser, TestDbContext>();
        services.AddAuthEndpoints<TestAppUser, TestDbContext>(o =>
        {
            o.Passkeys.Enabled = false;
            o.RequireConfirmedAccount = false;
            o.ConfigureIdentity = identity => identity.Password.RequiredLength = 8;
        });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<IdentityOptions>>().Value;
        Assert.False(options.SignIn.RequireConfirmedAccount);
        Assert.Equal(8, options.Password.RequiredLength);
    }

    [Fact]
    public void SecondFacadeCall_RegistersRolesWhenTheFirstCallDidNot()
    {
        var services = new ServiceCollection();
        services.AddDbContext<TestRolesDbContext>(o => o.UseInMemoryDatabase("identity-late-roles"));
        services.AddAuthEndpointsIdentity<TestAppUser, TestRolesDbContext>();
        services.AddAuthEndpoints<TestAppUser, IdentityRole, TestRolesDbContext>(o => o.Passkeys.Enabled = false);

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetService<RoleManager<IdentityRole>>());
        Assert.NotNull(provider.GetService<IRoleStore<IdentityRole>>());
    }

    [Fact]
    public void SecondFacadeCall_SameRoleType_DoesNotThrow()
    {
        var services = new ServiceCollection();
        services.AddDbContext<TestRolesDbContext>(o => o.UseInMemoryDatabase("identity-same-role"));
        services.AddAuthEndpoints<TestAppUser, IdentityRole, TestRolesDbContext>(o => o.Passkeys.Enabled = false);
        services.AddAuthEndpoints<TestAppUser, IdentityRole, TestRolesDbContext>(o => o.Passkeys.Enabled = false);

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetService<RoleManager<IdentityRole>>());
    }

    [Fact]
    public void SecondFacadeCall_ConflictingRoleType_Throws()
    {
        var services = new ServiceCollection();
        services.AddDbContext<TestRolesDbContext>(o => o.UseInMemoryDatabase("identity-role-conflict"));
        services.AddAuthEndpoints<TestAppUser, IdentityRole, TestRolesDbContext>(o => o.Passkeys.Enabled = false);

        var conflict = Assert.Throws<InvalidOperationException>(() =>
            services.AddAuthEndpoints<TestAppUser, OtherRole, TestRolesDbContext>(o => o.Passkeys.Enabled = false));
        Assert.Contains("RoleManager<IdentityRole>", conflict.Message, StringComparison.Ordinal);
        Assert.Contains("RoleManager<OtherRole>", conflict.Message, StringComparison.Ordinal);
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

    private sealed class OtherRole;
}
