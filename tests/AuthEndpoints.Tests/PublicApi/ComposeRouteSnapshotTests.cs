using AuthEndpoints.Identity;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests.PublicApi;

/// <summary>
/// Route list of the 3.x composites, captured against 3.3.0. Later refactors must keep this surface stable.
/// </summary>
public class ComposeRouteSnapshotTests
{
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
