using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.Tests;

public class IdentityManagementCompositionTests
{
    [Fact]
    public async Task CookieAuthAlone_HasNoRegisterEndpoint()
    {
        await using var host = await StartHostAsync(map: app =>
        {
            app.MapGroup("/identity").MapCookieAuthEndpoints<TestAppUser>();
        });

        var client = host.GetTestClient();
        var register = await client.PostAsJsonAsync("/identity/register", new
        {
            email = $"alone-{Guid.NewGuid():N}@test.local",
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.NotFound, register.StatusCode);

        var csrf = await client.GetAsync("/identity/csrfToken");
        Assert.Equal(HttpStatusCode.OK, csrf.StatusCode);
    }

    [Fact]
    public async Task ManagementPlusCookie_RegisterAndLogin()
    {
        await using var host = await StartHostAsync(map: app =>
        {
            var group = app.MapGroup("/identity");
            group.MapIdentityManagementApi<TestAppUser>();
            group.MapCookieAuthEndpoints<TestAppUser>();
        });

        var client = host.GetTestClient();
        var email = $"mgmt-{Guid.NewGuid():N}@test.local";

        var register = await client.PostAsJsonAsync("/identity/register", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var login = await client.PostAsJsonAsync("/identity/login", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.True(login.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task ManagementPlusJwt_RegisterCreateAndManageInfo()
    {
        await using var host = await StartHostAsync(
            configureServices: services =>
            {
                services.AddJwtEndpoints<TestAppUser, TestDbContext>(o =>
                {
                    o.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
                });
            },
            map: app =>
            {
                app.MapGroup("/account").MapIdentityManagementApi<TestAppUser>();
                app.MapGroup("/auth").MapJwtAuthEndpoints<TestAppUser>();
            });

        var client = host.GetTestClient();
        var email = $"jwt-mgmt-{Guid.NewGuid():N}@test.local";

        var register = await client.PostAsJsonAsync("/account/register", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var create = await client.PostAsJsonAsync("/auth/create", new
        {
            email,
            password = TestHelpers.DefaultPassword
        });
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);

        using var doc = System.Text.Json.JsonDocument.Parse(await create.Content.ReadAsStringAsync());
        var accessToken = TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken");
        Assert.False(string.IsNullOrWhiteSpace(accessToken));

        using var infoRequest = new HttpRequestMessage(HttpMethod.Get, "/account/manage/info");
        infoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var info = await client.SendAsync(infoRequest);
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);
    }

    private static async Task<WebApplication> StartHostAsync(
        Action<IServiceCollection>? configureServices = null,
        Action<WebApplication>? map = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.WebHost.UseTestServer();

        var dbName = "MgmtComp_" + Guid.NewGuid().ToString("N");
        builder.Services.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase(dbName));
        builder.Services
            .AddIdentityApiEndpoints<TestAppUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredLength = 6;
            })
            .AddEntityFrameworkStores<TestDbContext>()
            .AddDefaultTokenProviders();

        builder.Services.AddAuthorization();
        builder.Services.AddAntiforgery();
        builder.Services.AddCookieAuthEndpoints();
        configureServices?.Invoke(builder.Services);

        var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            await db.Database.EnsureCreatedAsync();
        }

        app.UseAuthentication();
        app.UseAuthorization();
        app.UseRateLimiter();
        app.UseAntiforgery();
        map?.Invoke(app);
        await app.StartAsync();
        return app;
    }
}
