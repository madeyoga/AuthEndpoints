using AuthEndpoints.External.OAuth;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth.Tests;

public class JwtExternalBodyTransportTests
{
    [Fact]
    public async Task BodyTransport_FailsStartup_AndStoresNoRefreshToken()
    {
        await using var app = Build(RefreshTokenTransport.Body);
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ExternalJwtDb>();
        await db.Database.EnsureCreatedAsync();

        var resolved = Assert.Throws<OptionsValidationException>(() =>
            scope.ServiceProvider.GetRequiredService<IExternalLoginCompleter<ExternalJwtUser>>());
        Assert.Contains(JwtExternalBodyTransportValidator.Message, resolved.Failures);

        var startup = await Assert.ThrowsAnyAsync<Exception>(() => app.StartAsync());
        Assert.Contains(JwtExternalBodyTransportValidator.Message, startup.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, await db.Set<RefreshToken>().CountAsync());
    }

    [Fact]
    public async Task BodyTransport_CompleteAsync_ThrowsBeforeCreatingAToken()
    {
        var services = new ServiceCollection();
        services.AddOptions<JwtSessionOptions>()
            .Configure(options => options.RefreshTokenTransport = RefreshTokenTransport.Body);
        using var provider = services.BuildServiceProvider();
        var refresh = new RejectingRefreshTokens();
        var completer = new JwtExternalLoginCompleter<ExternalJwtUser>(
            null!,
            null!,
            refresh,
            new RefreshTokenCookieWriter(),
            Options.Create(new ExternalAuthOptions()));
        var http = new DefaultHttpContext { RequestServices = provider };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            completer.CompleteAsync(http, new ExternalJwtUser(), null!, "/", CancellationToken.None));

        Assert.Equal(JwtExternalBodyTransportValidator.Message, error.Message);
        Assert.Equal(0, refresh.CreateCalls);
    }

    [Fact]
    public async Task CookieTransport_Starts()
    {
        await using var app = Build(RefreshTokenTransport.Cookie);
        await app.StartAsync();
        await app.StopAsync();
    }

    private static WebApplication Build(RefreshTokenTransport transport)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Environment.EnvironmentName = Environments.Development;
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var dbPath = Path.Combine(Path.GetTempPath(), $"ae-jwt-external-{Guid.NewGuid():N}.sqlite");
        builder.Services.AddDbContext<ExternalJwtDb>(options => options.UseSqlite($"Data Source={dbPath}"));
        builder.Services.AddIdentityCore<ExternalJwtUser>()
            .AddEntityFrameworkStores<ExternalJwtDb>()
            .AddSignInManager()
            .AddDefaultTokenProviders();
        builder.Services.AddJwtEndpoints<ExternalJwtUser, ExternalJwtDb>(options =>
        {
            options.Issuer = "https://jwt.example";
            options.Audience = "https://jwt.example";
            options.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
        });
        builder.Services.Configure<JwtSessionOptions>(options => options.RefreshTokenTransport = transport);
        builder.Services.AddExternalAuthEndpoints<ExternalJwtUser>()
            .AddCompleter<JwtExternalLoginCompleter<ExternalJwtUser>>();
        return builder.Build();
    }

    private sealed class ExternalJwtDb : IdentityDbContext<ExternalJwtUser>
    {
        public ExternalJwtDb(DbContextOptions<ExternalJwtDb> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.UseRefreshToken();
        }
    }

    private sealed class ExternalJwtUser : IdentityUser;

    private sealed class RejectingRefreshTokens : IRefreshTokenService
    {
        public int CreateCalls { get; private set; }

        public Task<RefreshToken> CreateAsync(string userId, string securityStamp, string? familyId = null)
        {
            CreateCalls++;
            throw new InvalidOperationException("CreateAsync must not run.");
        }

        public Task<RefreshToken?> GetRefreshTokenAsync(string rawToken) => Task.FromResult<RefreshToken?>(null);

        public bool IsValid(RefreshToken refreshToken) => false;

        public Task RevokeAsync(RefreshToken refreshToken) => Task.CompletedTask;

        public Task RevokeFamilyAsync(string familyId) => Task.CompletedTask;

        public Task<RefreshToken?> RotateAsync(RefreshToken refreshToken, string securityStamp) =>
            Task.FromResult<RefreshToken?>(null);
    }
}
