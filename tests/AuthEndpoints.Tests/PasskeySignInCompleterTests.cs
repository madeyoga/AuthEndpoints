using System.Text.Json;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Tests;

public class PasskeySignInCompleterTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public PasskeySignInCompleterTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public void TestHost_RegistersIdentityPasskeySignInCompleterByDefault()
    {
        using var scope = _factory.Services.CreateScope();
        var completer = scope.ServiceProvider.GetRequiredService<IPasskeySignInCompleter<TestAppUser>>();
        Assert.IsType<IdentityPasskeySignInCompleter<TestAppUser>>(completer);
    }

    [Fact]
    public void Facade_RegistersIdentityPasskeySignInCompleterByDefault()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(o =>
            o.UseInMemoryDatabase("PasskeyCompleterFacade_" + Guid.NewGuid().ToString("N")));
        builder.Services.AddAuthEndpoints<TestAppUser, TestDbContext>(o =>
        {
            o.Passkeys.ServerDomain = "localhost";
            o.RequireEmailSenderInProduction = false;
        });
        builder.Services.AddTransient<IEmailSender<TestAppUser>, TestEmailSender>();

        using var app = builder.Build();
        using var scope = app.Services.CreateScope();
        var completer = scope.ServiceProvider.GetRequiredService<IPasskeySignInCompleter<TestAppUser>>();
        Assert.IsType<IdentityPasskeySignInCompleter<TestAppUser>>(completer);
    }

    [Fact]
    public void AddPasskeySignInCompleter_ReplacesDefaultWithJwtCompleter()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<TestDbContext>(o =>
            o.UseInMemoryDatabase("PasskeyCompleterReplace_" + Guid.NewGuid().ToString("N")));
        services
            .AddIdentityApiEndpoints<TestAppUser>(o =>
            {
                o.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            })
            .AddEntityFrameworkStores<TestDbContext>()
            .AddDefaultTokenProviders();
        services.AddJwtEndpoints<TestAppUser, TestDbContext>(o =>
        {
            o.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
        });
        services.AddPasskeyEndpoints<TestAppUser>();
        services.AddPasskeySignInCompleter<TestAppUser, JwtPasskeySignInCompleter<TestAppUser>>();

        using var sp = services.BuildServiceProvider();
        using var scope = sp.CreateScope();
        var completer = scope.ServiceProvider.GetRequiredService<IPasskeySignInCompleter<TestAppUser>>();
        Assert.IsType<JwtPasskeySignInCompleter<TestAppUser>>(completer);
    }

    [Fact]
    public async Task JwtPasskeySignInCompleter_IssuesAccessTokenAndRefreshCookie()
    {
        var email = $"passkey-jwt-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email);

        using var scope = _factory.Services.CreateScope();
        var completer = ActivatorUtilities.CreateInstance<JwtPasskeySignInCompleter<TestAppUser>>(
            scope.ServiceProvider);

        var httpContext = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider
        };
        httpContext.Request.Scheme = "https";
        httpContext.Response.Body = new MemoryStream();

        var result = await completer.CompleteAsync(
            httpContext,
            user,
            new PasskeySignInCompletionContext { Kind = PasskeySignInKind.Login },
            CancellationToken.None);

        await result.ExecuteAsync(httpContext);

        Assert.Equal(StatusCodes.Status200OK, httpContext.Response.StatusCode);
        Assert.Contains(
            httpContext.Response.Headers.SetCookie,
            static c => c is not null && c.Contains(RefreshTokenCookieWriter.CookieName, StringComparison.Ordinal));

        httpContext.Response.Body.Position = 0;
        using var doc = await JsonDocument.ParseAsync(httpContext.Response.Body);
        Assert.True(doc.RootElement.TryGetProperty("accessToken", out var accessToken));
        Assert.False(string.IsNullOrEmpty(accessToken.GetString()));
        Assert.Equal("Bearer", doc.RootElement.GetProperty("tokenType").GetString());
    }
}
