using Demo.Data;
using Demo.Infrastructure;
using Demo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthEndpoints;
using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

DotNetEnv.Env.Load();

builder.Services.AddOpenApi();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddDbContext<AppDbContext>(o =>
{
    o.UseSqlite(Environment.GetEnvironmentVariable("DB_CONNECTION_STRING")!);
});

builder.Services
    .AddAuthEndpoints<AppUser, AppDbContext>(o =>
    {
        o.IdentityPath = "/auth/cookie";
        o.PasskeyPath = "/auth/passkey";
        o.Passkeys.ServerDomain = "localhost";
        o.RequireConfirmedAccount = true;
        o.Jwt.Enabled = true;
        o.Jwt.Path = "/auth/jwt";
        o.Jwt.Configure = jwt =>
        {
            jwt.SigningOptions.SymmetricKey =
                Environment.GetEnvironmentVariable("JWT_SYMMETRIC_KEY")
                ?? "DemoOnly_ChangeMe_AuthEndpoints_Jwt_SigningKey_32+";
        };
    })
    .AddRoles<AppRole>();

builder.Services.AddTransient<IEmailSender<AppUser>, ConsoleEmailSender>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}
else
{
    app.UseHttpsRedirection();
}

app.UseAuthEndpoints();
app.UseMiddleware<AntiforgeryEnforcementMiddleware>();

app.MapAuthEndpoints<AppUser>();

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
