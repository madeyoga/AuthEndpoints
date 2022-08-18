using AuthEndpoints.Core;
using AuthEndpoints.MinimalApi;
using AuthEndpoints.TokenAuth;
using AuthEndpoints.TokenAuth.Tests.Web.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<MyDbContext>(options =>
{
    if (builder.Environment.IsDevelopment())
    {
        //options.UseSqlite(builder.Configuration.GetConnectionString("DataSQLiteConnection"));
        options.UseInMemoryDatabase(databaseName: "Test");
    }
});

builder.Services.AddIdentityCore<IdentityUser>(option =>
{
    option.User.RequireUniqueEmail = true;
    option.Password.RequireDigit = false;
    option.Password.RequireNonAlphanumeric = false;
    option.Password.RequireUppercase = false;
    option.Password.RequiredLength = 0;
})
.AddEntityFrameworkStores<MyDbContext>()
.AddDefaultTokenProviders();

builder.Services.AddAuthEndpointsCore<IdentityUser>()
    .AddBasicAuthenticationEndpoints();

builder.Services.AddTokenAuthEndpoints<IdentityUser, MyDbContext>();

//builder.Services.AddAuthentication("TokenAuth")
//    .AddScheme<TokenBearerOptions, TokenBearerHandler<string, IdentityUser, MyDbContext>>("TokenAuth", "Token Authentication", null);

//builder.Services.AddScoped<AuthTokenValidator<string, IdentityUser, MyDbContext>>();
//builder.Services.AddScoped<AuthTokenGenerator>();
//builder.Services.AddScoped<TokenRepository<string, IdentityUser, MyDbContext>>();
//builder.Services.AddScoped<IAuthenticator<IdentityUser>, TokenAuthService<IdentityUser>>();
//builder.Services.AddEndpointDefinition<TokenAuthEndpoints<string, IdentityUser>>();

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

app.MapEndpoints();

app.Run();
