using AuthEndpoints;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using AuthEndpoints.ReAuth;
using AuthEndpoints.Tests;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var dbName = builder.Configuration["TestDbName"] ?? "AuthEndpointsTests";
var hostMode = builder.Configuration["AE_HOST_MODE"] ?? "compose";
var useBearerFacade = string.Equals(hostMode, "bearer-facade", StringComparison.OrdinalIgnoreCase);

builder.Services.AddDbContext<TestDbContext>(options =>
    options.UseInMemoryDatabase(dbName));

if (useBearerFacade)
{
    builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(
        AuthEndpointsSignIn.IdentityBearer,
        o =>
        {
            o.RequireConfirmedAccount = false;
            o.Passkeys.ServerDomain = "localhost";
            o.ConfigureIdentity = ConfigureTestIdentity;
            o.Jwt.Enabled = true;
            o.Jwt.Configure = jwt =>
            {
                jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            };
        });
}
else
{
    builder.Services
        .AddIdentityApiEndpoints<TestAppUser>(ConfigureTestIdentity)
        .AddEntityFrameworkStores<TestDbContext>()
        .AddDefaultTokenProviders();

    builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(options =>
    {
        options.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
    });

    builder.Services.AddAuthorization();
    builder.Services.AddAntiforgery();
    builder.Services.AddCookieAuthEndpoints();
    builder.Services.AddPasskeyEndpoints<TestAppUser>();
}

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
    await db.Database.EnsureCreatedAsync();
}

if (useBearerFacade)
{
    app.UseAuthEndpoints();
    app.MapAuthEndpoints<TestAppUser>();
}
else
{
    app.UseAuthentication();
    app.UseAuthorization();
    app.UseRateLimiter();
    app.UseAntiforgery();

    app.MapGroup("/auth").MapJwtAuthEndpoints<TestAppUser>();

    var identity = app.MapGroup("/identity");
    identity.MapIdentityManagementApi<TestAppUser>();
    identity.MapCookieAuthEndpoints<TestAppUser>();

    var identityBearer = app.MapGroup("/identity/bearer");
    identityBearer.MapIdentityManagementApi<TestAppUser>(
        $"MapIdentityManagementApi-bearer-{nameof(TestAppUser)}-confirmEmail");
    identityBearer.MapBearerAuthEndpoints<TestAppUser>();

    app.MapGroup("/account").MapPasskeyEndpoints<TestAppUser>();
}

MapTestOnlyEndpoints(app);

app.Run();

static void ConfigureTestIdentity(IdentityOptions options)
{
    options.SignIn.RequireConfirmedAccount = false;
    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;
}

static void MapTestOnlyEndpoints(WebApplication app)
{
    app.MapPost("/test/csrf", () => Results.Ok()).RequireAntiforgery();

    app.MapGet("/test/reauth", () => Results.Ok()).RequireReauth();

    app.MapPost("/test/csrf-auth", () => Results.Ok())
        .RequireAuthorization(new AuthorizeAttribute
        {
            AuthenticationSchemes = $"{JwtBearerDefaults.AuthenticationScheme},{IdentityConstants.ApplicationScheme}"
        })
        .RequireAntiforgery();
}

public partial class Program;
