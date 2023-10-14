using System.Reflection;
using System.Text;
using AuthEndpoints.Demo.Data;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Core;
using AuthEndpoints.SimpleJwt;
using AuthEndpoints.Users;
using Microsoft.EntityFrameworkCore;
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

    // To Enable authorization using Swagger (JWT)
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer 12345abcdef\"",
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
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

    options.UseSimpleJwtEntities();
});

// Populate default identityuser objects.
builder.Services.AddScoped<UserDataSeeder>();

builder.Services.AddIdentityCore<MyCustomIdentityUser>(option =>
{
    option.User.RequireUniqueEmail = true;
    option.Password.RequireDigit = false;
    option.Password.RequireNonAlphanumeric = false;
    option.Password.RequireUppercase = false;
    option.Password.RequiredLength = 0;
});

builder.Services.AddUsersApiEndpoints<MyCustomIdentityUser, MyDbContext>(options =>
{
    options.EmailConfirmationUrl = "localhost:3000/account/email/confirm/{uid}/{token}";
    options.PasswordResetUrl = "localhost:3000/account/password/reset/{uid}/{token}";
});

builder.Services.AddSimpleJwtEndpoints<MyCustomIdentityUser, MyDbContext>(options =>
{
    options.AccessSigningOptions = new JwtSigningOptions()
    {
        SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("yn4$#cr=+i@eljzlhhr2xlgf98aud&(3&!po3r60wlm^3*huh#")),
        Algorithm = SecurityAlgorithms.HmacSha256,
        ExpirationMinutes = 90,
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
	app.UseSwaggerUI();

    using (var scope = app.Services.CreateScope())
    {
        var dbContext = scope.ServiceProvider.GetRequiredService<MyDbContext>();
        dbContext.Database.EnsureCreated();

        var UserDataSeeder = scope.ServiceProvider.GetRequiredService<UserDataSeeder>();
        UserDataSeeder.Populate();
    }
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapEndpoints();

//app.MapGroup("/auth")
//   .MapSimpleJwtApi<MyCustomIdentityUser>()
//   .WithTags("Authentication and Authorization");

//app.MapGroup("/account")
//   .MapUsersApi<MyCustomIdentityUser>()
//   .WithTags("Users");

app.Run();
