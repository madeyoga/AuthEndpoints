using System.Reflection;
using AuthEndpoints;
using AuthEndpoints.Demo.Data;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.MinimalApi;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
		TermsOfService = new Uri("https://example.com/terms"),
		Contact = new OpenApiContact
		{
			Name = "contact",
			Email = string.Empty,
			Url = new Uri("https://example.com/contact"),
		},
		License = new OpenApiLicense
		{
			Name = "Use under MIT",
			Url = new Uri("https://example.com/license"),
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
		options.UseSqlite(builder.Configuration.GetConnectionString("DataSQLiteConnection"));
	}
});

builder.Services.AddIdentityCore<MyCustomIdentityUser>(option =>
{
    option.User.RequireUniqueEmail = true;
    option.Password.RequireDigit = false;
    option.Password.RequireNonAlphanumeric = false;
    option.Password.RequireUppercase = false;
    option.Password.RequiredLength = 0;
})
    .AddEntityFrameworkStores<MyDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthEndpoints<string, MyCustomIdentityUser>(options =>
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
    .AddAllEndpointDefinitions()
    .AddJwtBearerAuthScheme();

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
app.MapAuthEndpoints();

app.Run();
