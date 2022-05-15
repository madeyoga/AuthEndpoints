using AuthEndpoints.Demo.Data;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Demo.Services;
using AuthEndpoints.Extensions;
using AuthEndpoints.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Reflection;
using System.Text;

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

var accessTokenValidationParameters = new TokenValidationParameters()
{
	IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("9GHdZCAJ2XaXFuhOhIt21zxJCWk7obnzcHqDB4t7X0WcvrB8bzvkyEFlIMRXO4o-y3eQs8e4uDiFJcAhnFOiE6I45aJQi22DEy5epVLyQIVFYI-dbumj8ieK1sKMPySfN9S4eliQznJYL82XhtI_8U1EvEL2_C7PX4rTR0Xjf8k")),
	ValidIssuer = "https://localhost:8000",
	ValidAudience = "https://localhost:8000",
	ValidateIssuerSigningKey = true,
	ValidateIssuer = true,
	ValidateAudience = true,
	ClockSkew = TimeSpan.Zero,
};

var refreshTokenValidationParameters = new TokenValidationParameters()
{
	IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("8GHdZCAJ2XaXFuhOhIt21zxJCWk7obnzcHqDB4t7X0WcvrB8bzvkyEFlIMRXO4o-y3eQs8e4uDiFJcAhnFOiE6I45aJQi22DEy5epVLyQIVFYI-dbumj8ieK1sKMPySfN9S4eliQznJYL82XhtI_8U1EvEL2_C7PX4rTR0Xjf8k")),
	ValidIssuer = "https://localhost:8000",
	ValidAudience = "https://localhost:8000",
	ValidateIssuerSigningKey = true,
	ValidateIssuer = true,
	ValidateAudience = true,
	ClockSkew = TimeSpan.Zero,
};

builder.Services.AddAuthEndpoints<string, MyCustomIdentityUser>(new AuthEndpointsOptions()
{
	AccessTokenSecret = "9GHdZCAJ2XaXFuhOhIt21zxJCWk7obnzcHqDB4t7X0WcvrB8bzvkyEFlIMRXO4o-y3eQs8e4uDiFJcAhnFOiE6I45aJQi22DEy5epVLyQIVFYI-dbumj8ieK1sKMPySfN9S4eliQznJYL82XhtI_8U1EvEL2_C7PX4rTR0Xjf8k",	
	RefreshTokenSecret = "8GHdZCAJ2XaXFuhOhIt21zxJCWk7obnzcHqDB4t7X0WcvrB8bzvkyEFlIMRXO4o-y3eQs8e4uDiFJcAhnFOiE6I45aJQi22DEy5epVLyQIVFYI-dbumj8ieK1sKMPySfN9S4eliQznJYL82XhtI_8U1EvEL2_C7PX4rTR0Xjf8k",
	AccessTokenExpirationMinutes = 15,
	RefreshTokenExpirationMinutes = 6000,
	Audience = "https://localhost:8000",
	Issuer = "https://localhost:8000",
	AccessTokenValidationParameters = accessTokenValidationParameters,
	RefreshTokenValidationParameters = refreshTokenValidationParameters
}).AddJwtBearerAuthenticationScheme(accessTokenValidationParameters)
	.AddClaimsProvider<MyClaimsProvider>();

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
