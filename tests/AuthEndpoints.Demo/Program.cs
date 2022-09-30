﻿using System.Reflection;
using System.Text;
using AuthEndpoints.Core;
using AuthEndpoints.Core.Services;
using AuthEndpoints.Demo.Data;
using AuthEndpoints.Demo.Endpoints;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.MinimalApi;
using AuthEndpoints.SimpleJwt;
using AuthEndpoints.SimpleJwt.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();

builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
	options.SwaggerDoc("v1", new OpenApiInfo()
	{
		Title = "My API - v1",
		Version = "v1",
		Description = "A simple example ASP.NET Core Web API",
		Contact = new OpenApiContact
		{
			Name = "contact",
			Email = string.Empty,
			Url = new Uri("https://github.com/madeyoga/AuthEndpoints/issues"),
		},
		License = new OpenApiLicense
		{
			Name = "Use under MIT",
			Url = new Uri("https://github.com/madeyoga/AuthEndpoints/blob/main/LICENSE"),
		}
	});

	var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
	var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
	options.IncludeXmlComments(xmlPath);
});

builder.Services.AddDbContext<MyDbContext>(options =>
{
	if (builder.Environment.IsDevelopment())
	{
        //options.UseSqlite(builder.Configuration.GetConnectionString("DataSQLiteConnection"));
        options.UseInMemoryDatabase(databaseName: "Test");
    }
});

builder.Services.AddIdentityCore<MyCustomIdentityUser>(option =>
{
    option.User.RequireUniqueEmail = true;
    option.Password.RequireDigit = false;
    option.Password.RequireNonAlphanumeric = false;
    option.Password.RequireUppercase = false;
    option.Password.RequiredLength = 0;
});

builder.Services.AddAuthEndpointsCore<MyCustomIdentityUser, MyDbContext>(options =>
{
    options.EmailConfirmationUrl = "localhost:3000/account/email/confirm/{uid}/{token}";
    options.PasswordResetUrl = "localhost:3000/account/password/reset/{uid}/{token}";
    options.EmailOptions = new EmailOptions()
    {
        Host = "smtp.gmail.com",
        From = Environment.GetEnvironmentVariable("GOOGLE_MAIL_APP_USER")!,
        Port = 587,
        User = Environment.GetEnvironmentVariable("GOOGLE_MAIL_APP_USER")!,
        Password = Environment.GetEnvironmentVariable("GOOGLE_MAIL_APP_PASSWORD")!,
    };
})
.AddUsersApiEndpoints()
.Add2FAEndpoints();

builder.Services.AddSimpleJwtEndpoints<MyCustomIdentityUser, MyDbContext>(options =>
{
    options.UseCookie = false;

    options.AccessSigningOptions = new JwtSigningOptions()
    {
        SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("yn4$#cr=+i@eljzlhhr2xlgf98aud&(3&!po3r60wlm^3*huh#")),
        Algorithm = SecurityAlgorithms.HmacSha256,
        ExpirationMinutes = 120,
    };

    options.RefreshSigningOptions = new JwtSigningOptions()
    {
        SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("e_qmg*)=vr9yxpp^g^#((wkwk7fh#+3qy!zzq+r-hifw2(_u+=")),
        Algorithm = SecurityAlgorithms.HmacSha256,
        ExpirationMinutes = 2880,
    };
});

// additional services for JwtCookie Api
builder.Services.AddHttpContextAccessor();
builder.Services.TryAddScoped<ILoginService, JwtHttpOnlyCookieLoginService>();
builder.Services.TryAddScoped<JwtHttpOnlyCookieLoginService>();
builder.Services.AddEndpointDefinition<JwtCookieEndpoints>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
	app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapEndpoints();

app.Run();
