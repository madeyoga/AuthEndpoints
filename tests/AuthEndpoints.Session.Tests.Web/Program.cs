using AuthEndpoints.Core;
using AuthEndpoints.MinimalApi;
using AuthEndpoints.Session;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
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

builder.Services.AddAuthEndpointsCore<IdentityUser, MyDbContext>()
    .AddUsersApiEndpoints();
builder.Services.AddSessionEndpoints<IdentityUser>();

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
