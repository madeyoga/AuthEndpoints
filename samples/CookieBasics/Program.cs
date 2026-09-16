using AuthEndpoints;
using CookieBasics;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddAuthEndpoints<IdentityUser, AppDbContext>(options =>
{
    options.Passkeys.Enabled = false;
    options.Jwt.Enabled = false;
});

builder.Services.AddTransient<IEmailSender<IdentityUser>, ConsoleEmailSender>();

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddOpenApi();
}

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.EnsureCreatedAsync();
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseAuthEndpoints();
app.MapAuthEndpoints<IdentityUser>();

app.Run();
