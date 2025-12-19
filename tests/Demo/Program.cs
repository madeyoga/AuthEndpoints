using Demo.Data;
using Demo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthEndpoints.Jwt;
using AuthEndpoints.Identity;
using AuthEndpoints.Passkey;

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

// builder.Services.Configure<IdentityPasskeyOptions>(options =>
// {
//     options.ServerDomain = "example.com";
// });

builder.Services.AddJwtEndpoints<AppUser, AppDbContext>();

builder.Services.AddAuthorization();

builder.Services.AddAntiforgery();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    app.UseHttpsRedirection();
}

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();
app.UseMiddleware<AntiforgeryEnforcementMiddleware>();

// app.MapGroup("account").MapAccountApi<AppUser>().WithTags("Account management");
app.MapGroup("auth").MapJwtAuthEndpoints<AppUser>().WithTags("Jwt");
app.MapGroup("identity").MapCookieAuthEndpoints<AppUser>().WithTags("Identity: Cookie scheme");

app.MapGroup("/account").MapPasskeyEndpoints<AppUser>();

app.MapPost("/test/csrf", () =>
{
    return Results.Ok();
}).EnableAntiforgery();

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

