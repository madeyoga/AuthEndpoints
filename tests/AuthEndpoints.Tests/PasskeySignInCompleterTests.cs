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
    public void AddPasskeyEndpoints_RegistersDefaultPasskeyUserIdFactory()
    {
        using var scope = _factory.Services.CreateScope();
        var factory = scope.ServiceProvider.GetRequiredService<IPasskeyUserIdFactory>();
        Assert.IsType<DefaultPasskeyUserIdFactory>(factory);
        Assert.True(Guid.TryParse(factory.CreateUserId(), out _), "Default factory should mint a Guid-shaped id.");
    }

    [Fact]
    public void AddPasskeyUserIdFactory_ReplacesDefaultFactory()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<TestDbContext>(o =>
            o.UseInMemoryDatabase("PasskeyUserIdFactoryReplace_" + Guid.NewGuid().ToString("N")));
        services
            .AddIdentityApiEndpoints<TestAppUser>(o =>
            {
                o.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            })
            .AddEntityFrameworkStores<TestDbContext>()
            .AddDefaultTokenProviders();
        services.AddPasskeyEndpoints<TestAppUser>();
        services.AddPasskeyUserIdFactory(() => "replaced-user-id");

        using var sp = services.BuildServiceProvider();
        var factory = sp.GetRequiredService<IPasskeyUserIdFactory>();
        Assert.Equal("replaced-user-id", factory.CreateUserId());
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

        var httpContext = NewHttpContext(scope.ServiceProvider);

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

    [Fact]
    public async Task IdentityPasskeySignInCompleter_Login_Unconfirmed_DoesNotSignIn()
    {
        await using var sp = BuildRequireConfirmedAccountServices();
        var user = await SeedUnconfirmedAsync(sp);

        using var scope = sp.CreateScope();
        var completer = ActivatorUtilities.CreateInstance<IdentityPasskeySignInCompleter<TestAppUser>>(
            scope.ServiceProvider);

        var httpContext = NewHttpContext(scope.ServiceProvider);
        var result = await completer.CompleteAsync(
            httpContext,
            user,
            new PasskeySignInCompletionContext { Kind = PasskeySignInKind.Login },
            CancellationToken.None);

        await result.ExecuteAsync(httpContext);

        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
        Assert.DoesNotContain(
            httpContext.Response.Headers.SetCookie,
            static c => c is not null && c.Contains(".AspNetCore.", StringComparison.Ordinal));
    }

    [Fact]
    public async Task IdentityPasskeySignInCompleter_Register_Unconfirmed_DoesNotSignIn()
    {
        await using var sp = BuildRequireConfirmedAccountServices();
        var user = await SeedUnconfirmedAsync(sp);

        using var scope = sp.CreateScope();
        var completer = ActivatorUtilities.CreateInstance<IdentityPasskeySignInCompleter<TestAppUser>>(
            scope.ServiceProvider);

        var httpContext = NewHttpContext(scope.ServiceProvider);
        var result = await completer.CompleteAsync(
            httpContext,
            user,
            new PasskeySignInCompletionContext
            {
                Kind = PasskeySignInKind.Register,
                CredentialId = [1, 2, 3, 4]
            },
            CancellationToken.None);

        await result.ExecuteAsync(httpContext);

        Assert.Equal(StatusCodes.Status200OK, httpContext.Response.StatusCode);
        Assert.DoesNotContain(
            httpContext.Response.Headers.SetCookie,
            static c => c is not null && c.Contains(".AspNetCore.", StringComparison.Ordinal));

        httpContext.Response.Body.Position = 0;
        using var doc = await JsonDocument.ParseAsync(httpContext.Response.Body);
        Assert.False(string.IsNullOrEmpty(
            TestHelpers.TryGetString(doc.RootElement, "credentialId", "CredentialId")));
    }

    [Fact]
    public async Task JwtPasskeySignInCompleter_Login_Unconfirmed_DoesNotIssueTokens()
    {
        await using var sp = BuildRequireConfirmedAccountServices();
        var user = await SeedUnconfirmedAsync(sp);

        using var scope = sp.CreateScope();
        var completer = ActivatorUtilities.CreateInstance<JwtPasskeySignInCompleter<TestAppUser>>(
            scope.ServiceProvider);

        var httpContext = NewHttpContext(scope.ServiceProvider);
        var result = await completer.CompleteAsync(
            httpContext,
            user,
            new PasskeySignInCompletionContext { Kind = PasskeySignInKind.Login },
            CancellationToken.None);

        await result.ExecuteAsync(httpContext);

        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
        Assert.DoesNotContain(
            httpContext.Response.Headers.SetCookie,
            static c => c is not null && c.Contains(RefreshTokenCookieWriter.CookieName, StringComparison.Ordinal));

        httpContext.Response.Body.Position = 0;
        if (httpContext.Response.Body.Length == 0)
        {
            return;
        }

        using var doc = await JsonDocument.ParseAsync(httpContext.Response.Body);
        Assert.False(doc.RootElement.TryGetProperty("accessToken", out _));
    }

    private static ServiceProvider BuildRequireConfirmedAccountServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<TestDbContext>(o =>
            o.UseInMemoryDatabase("PasskeyCanSignIn_" + Guid.NewGuid().ToString("N")));
        services
            .AddIdentityApiEndpoints<TestAppUser>(o =>
            {
                o.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                o.SignIn.RequireConfirmedAccount = true;
                o.Password.RequireDigit = false;
                o.Password.RequireLowercase = false;
                o.Password.RequireUppercase = false;
                o.Password.RequireNonAlphanumeric = false;
                o.Password.RequiredLength = 6;
            })
            .AddEntityFrameworkStores<TestDbContext>()
            .AddDefaultTokenProviders();
        services.AddJwtEndpoints<TestAppUser, TestDbContext>(o =>
        {
            o.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
        });
        services.AddPasskeyEndpoints<TestAppUser>();
        return services.BuildServiceProvider();
    }

    private static async Task<TestAppUser> SeedUnconfirmedAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        await db.Database.EnsureCreatedAsync();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var email = $"passkey-unconfirmed-{Guid.NewGuid():N}@test.local";
        var user = new TestAppUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = false
        };
        var create = await userManager.CreateAsync(user, TestHelpers.DefaultPassword);
        Assert.True(create.Succeeded, string.Join("; ", create.Errors.Select(e => e.Description)));
        return user;
    }

    private static DefaultHttpContext NewHttpContext(IServiceProvider services)
    {
        var httpContext = new DefaultHttpContext
        {
            RequestServices = services
        };
        httpContext.Request.Scheme = "https";
        httpContext.Response.Body = new MemoryStream();
        return httpContext;
    }
}
