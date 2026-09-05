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
var requireConfirmedAccount = IsTruthy(builder.Configuration["AE_REQUIRE_CONFIRMED_ACCOUNT"]);
var dbPath = Path.Combine(Path.GetTempPath(), $"AuthEndpointsTests-{dbName}.sqlite");

builder.Services.AddDbContext<TestDbContext>(options =>
    options.UseSqlite($"Data Source={dbPath}"));

builder.Services.AddSingleton<CapturingEmailSender>();
builder.Services.AddSingleton<IEmailSender<TestAppUser>>(sp => sp.GetRequiredService<CapturingEmailSender>());
builder.Services.AddSingleton<SoftwareWebAuthnAuthenticator>();

if (useBearerFacade)
{
    builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(
        AuthEndpointsSignIn.IdentityBearer,
        o =>
        {
            o.RequireConfirmedAccount = requireConfirmedAccount;
            o.Passkeys.ServerDomain = "localhost";
            o.ConfigureIdentity = identity => ConfigureTestIdentity(identity, requireConfirmedAccount);
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
        .AddIdentityApiEndpoints<TestAppUser>(identity => ConfigureTestIdentity(identity, requireConfirmedAccount))
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

static bool IsTruthy(string? value) =>
    string.Equals(value, "true", StringComparison.OrdinalIgnoreCase)
    || string.Equals(value, "1", StringComparison.OrdinalIgnoreCase);

static void ConfigureTestIdentity(IdentityOptions options, bool requireConfirmedAccount)
{
    options.SignIn.RequireConfirmedAccount = requireConfirmedAccount;
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

    app.MapGet("/test/mailbox", (CapturingEmailSender mailbox) => Results.Ok(mailbox.Snapshot()));

    app.MapPost("/test/webauthn/attestation", (
        TestWebAuthnRequest body,
        HttpContext context,
        SoftwareWebAuthnAuthenticator authenticator) =>
    {
        var origin = ResolveOrigin(body.Origin, context);
        var credentialJson = authenticator.CreateAttestation(body.OptionsJson, origin);
        return Results.Ok(new { credentialJson });
    });

    app.MapPost("/test/webauthn/assertion", (
        TestWebAuthnRequest body,
        HttpContext context,
        SoftwareWebAuthnAuthenticator authenticator) =>
    {
        var origin = ResolveOrigin(body.Origin, context);
        var credentialJson = authenticator.CreateAssertion(body.OptionsJson, origin, body.CredentialId);
        return Results.Ok(new { credentialJson });
    });
}

static string ResolveOrigin(string? origin, HttpContext context) =>
    string.IsNullOrWhiteSpace(origin)
        ? $"{context.Request.Scheme}://{context.Request.Host}"
        : origin;

internal sealed record TestWebAuthnRequest(string OptionsJson, string? Origin, string? CredentialId);

public partial class Program;
