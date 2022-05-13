using AuthEndpoints.Demo.Data;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Extensions;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddSwaggerGen();

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

builder.Services.AddAuthEndpoints<string, MyCustomIdentityUser>(builder.Configuration);

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
