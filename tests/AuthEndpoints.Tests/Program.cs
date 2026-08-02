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

builder.Services.AddDbContext<TestDbContext>(options =>
    options.UseInMemoryDatabase(dbName));

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

builder.Services.AddJwtEndpoints<TestAppUser, TestDbContext>(options =>
{
    options.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
});

builder.Services.AddAuthorization();
builder.Services.AddAntiforgery();
builder.Services.AddCookieAuthEndpoints();
builder.Services.AddPasskeyEndpoints<TestAppUser>();

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

app.MapGroup("/auth").MapJwtAuthEndpoints<TestAppUser>();

var identity = app.MapGroup("/identity");
identity.MapIdentityManagementApi<TestAppUser>();
identity.MapCookieAuthEndpoints<TestAppUser>();

var identityBearer = app.MapGroup("/identity/bearer");
identityBearer.MapIdentityManagementApi<TestAppUser>(
    $"MapIdentityManagementApi-bearer-{nameof(TestAppUser)}-confirmEmail");
identityBearer.MapBearerAuthEndpoints<TestAppUser>();

app.MapGroup("/account").MapPasskeyEndpoints<TestAppUser>();

// --- Test-only endpoints (not part of the AuthEndpoints library surface) ---

// Anonymous CSRF check via RequireAntiforgery endpoint filter (preferred over
// AntiforgeryEnforcementMiddleware / EnableAntiforgery metadata).
// Used by AntiforgeryBearerSkipTests: POST without token must return 400.
app.MapPost("/test/csrf", () => Results.Ok()).RequireAntiforgery();

// Verifies that ConfirmIdentity issued the short-lived ReAuth cookie.
// Used by ReAuthEndpointsTests after POST /identity/confirmIdentity.
app.MapGet("/test/reauth", () => Results.Ok()).RequireReauth();

// Authorized + RequireAntiforgery probe for CSRF bearer-skip vs cookie-require.
// Explicit AuthenticationSchemes are required: plain RequireAuthorization() only uses
// Identity's default cookie scheme, so a JWT Authorization header would get 401 and
// never reach the antiforgery filter. Listing Bearer + Application lets one endpoint
// cover both AntiforgeryBearerSkipTests cases (JWT without CSRF succeeds; cookie without CSRF fails).
app.MapPost("/test/csrf-auth", () => Results.Ok())
    .RequireAuthorization(new AuthorizeAttribute
    {
        AuthenticationSchemes = $"{JwtBearerDefaults.AuthenticationScheme},{IdentityConstants.ApplicationScheme}"
    })
    .RequireAntiforgery();

app.Run();

public partial class Program;
