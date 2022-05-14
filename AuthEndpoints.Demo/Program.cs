using AuthEndpoints.Demo.Data;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using System.Reflection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
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
			Name = "Shayne Boyer",
			Email = string.Empty,
			Url = new Uri("https://twitter.com/spboyer"),
		},
		License = new OpenApiLicense
		{
			Name = "Use under LICX",
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
	// For testing only, remove this for production
	option.Password.RequireDigit = false;
	option.Password.RequireNonAlphanumeric = false;
	option.Password.RequireUppercase = false;
	option.Password.RequiredLength = 0;
}).AddEntityFrameworkStores<MyDbContext>();

builder.Services.AddAuthEndpoints<string, MyCustomIdentityUser>();

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

app.Run();
