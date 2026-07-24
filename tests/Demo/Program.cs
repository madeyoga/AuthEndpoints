using Demo.Data;
using Demo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthEndpoints.Jwt;
using AuthEndpoints.Identity;
using AuthEndpoints.Passkey;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

DotNetEnv.Env.Load();

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddDbContext<AppDbContext>(o =>
{
    o.UseSqlite(Environment.GetEnvironmentVariable("DB_CONNECTION_STRING")!);
});
builder.Services
    .AddIdentityApiEndpoints<AppUser>(o =>
    {
        o.SignIn.RequireConfirmedAccount = true;
        o.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
    })
    .AddRoles<AppRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<IdentityPasskeyOptions>(options =>
{
    // Use the host that serves the app in development (adjust for production).
    options.ServerDomain = "localhost";
});

builder.Services.AddJwtEndpoints<AppUser, AppDbContext>(options =>
{
    // Demo-only stable key. Set a secret from configuration/environment in real apps.
    options.SigningOptions.SymmetricKey =
        Environment.GetEnvironmentVariable("JWT_SYMMETRIC_KEY")
        ?? "DemoOnly_ChangeMe_AuthEndpoints_Jwt_SigningKey_32+";
});

builder.Services.AddAuthorization();

builder.Services.AddAntiforgery();

builder.Services.AddCookieAuthEndpoints();
builder.Services.AddPasskeyEndpoints();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}
else
{
    app.UseHttpsRedirection();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.UseAntiforgery();
app.UseMiddleware<AntiforgeryEnforcementMiddleware>();

app.MapGroup("auth").MapJwtAuthEndpoints<AppUser>().WithTags("Jwt");
app.MapGroup("identity").MapCookieAuthEndpoints<AppUser>().WithTags("Identity: Cookie scheme");

app.MapGroup("/account").MapPasskeyEndpoints<AppUser>().WithTags("Passkeys");

app.MapPost("/test/csrf", () => Results.Ok()).EnableAntiforgery();

app.MapGet("/test/reauth", () => Results.Ok()).RequireReauth();

app.MapGet("createDefaultUser", async (UserManager<AppUser> userManager) =>
{
    var user = new AppUser()
    {
        UserName = "admin@authendpoints.id",
        Email = "admin@authendpoints.id"
    };

    await userManager.CreateAsync(user, "T3$ttest");

    return Results.Ok();
});

app.Run();
