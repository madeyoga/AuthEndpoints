using AuthEndpoints.Identity;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests.PublicApi;

public class FacadeRouteSnapshotTests
{
    [Fact]
    public Task Facade_Cookie_DefaultRouteSet()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(o =>
                {
                    o.Passkeys.ServerDomain = "localhost";
                });
                builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
            },
            app => app.MapAuthEndpoints<TestAppUser>());

        return Verifier.Verify(surface);
    }

    [Fact]
    public Task Facade_IdentityBearer_RouteSet()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(
                    AuthEndpointsSignIn.IdentityBearer,
                    o => o.Passkeys.ServerDomain = "localhost");
                builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
            },
            app => app.MapAuthEndpoints<TestAppUser>());

        return Verifier.Verify(surface);
    }

    [Fact]
    public Task Facade_IdentityBearer_WithJwt_RouteSet()
    {
        var surface = RouteSurface.Capture(
            builder =>
            {
                builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(
                    AuthEndpointsSignIn.IdentityBearer,
                    o =>
                    {
                        o.Passkeys.ServerDomain = "localhost";
                        o.Jwt.Enabled = true;
                        o.Jwt.Configure = jwt =>
                        {
                            jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
                        };
                    });
                builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();
            },
            app => app.MapAuthEndpoints<TestAppUser>());

        return Verifier.Verify(surface);
    }

    [Fact]
    public Task Compose_ManagementCookiePasskey_RouteSet()
    {
        var surface = RouteSurface.Capture(
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
                builder.Services.AddAuthorization();
                builder.Services.AddAntiforgery();
                builder.Services.AddCookieAuthEndpoints();
                builder.Services.AddPasskeyEndpoints<TestAppUser>();
            },
            app =>
            {
                var identity = app.MapGroup("/identity");
                identity.MapIdentityManagementApi<TestAppUser>();
                identity.MapCookieAuthEndpoints<TestAppUser>();
                app.MapGroup("/account").MapPasskeyEndpoints<TestAppUser>();
            });

        return Verifier.Verify(surface);
    }
}
