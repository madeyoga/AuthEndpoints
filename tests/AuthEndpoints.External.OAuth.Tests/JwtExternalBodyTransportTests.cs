using AuthEndpoints.External.OAuth;
using AuthEndpoints.Jwt;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.External.OAuth.Tests;

/// <summary>
/// External sign-in redirects, so it cannot hand a JWT session its refresh token in a response body.
/// Mapping it for a body-transport JWT session throws, and the JWT completer refuses before it stores a token.
/// </summary>
public class JwtExternalBodyTransportTests
{
    [Fact]
    public async Task BodyTransport_MapExternalForJwt_Throws()
    {
        await using var app = Build(RefreshTokenTransport.Body);

        var error = Assert.Throws<InvalidOperationException>(() =>
            app.MapGroup("/auth/external").MapExternalAuthEndpoints<ExternalJwtUser>(AuthEndpointsSession.Jwt));

        Assert.Equal(JwtExternalBodyTransport.Message, error.Message);
    }

    [Fact]
    public async Task CookieTransport_MapExternalForJwt_Starts()
    {
        await using var app = Build(RefreshTokenTransport.Cookie);
        app.MapGroup("/auth/external").MapExternalAuthEndpoints<ExternalJwtUser>(AuthEndpointsSession.Jwt);

        await app.StartAsync();
        await app.StopAsync();
    }

    [Fact]
    public async Task BodyTransport_JwtCompleter_RefusesExternalBeforeCreatingAToken()
    {
        var refresh = new RejectingRefreshTokens();
        await using var app = Build(RefreshTokenTransport.Body, refresh);
        await using var scope = app.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<ExternalJwtDb>().Database.EnsureCreatedAsync();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ExternalJwtUser>>();
        var user = new ExternalJwtUser { UserName = "external@example.com", Email = "external@example.com" };
        Assert.True((await users.CreateAsync(user)).Succeeded);
        var completer = scope.ServiceProvider.GetRequiredKeyedService<ISignInCompleter<ExternalJwtUser>>(SignInCompleters.Jwt);
        var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => completer.CompleteAsync(
            http,
            user,
            new SignInCompletionContext { Method = SignInMethod.External, ReturnUrl = "/" }));

        Assert.Equal(JwtExternalBodyTransport.Message, error.Message);
        Assert.Equal(0, refresh.CreateCalls);
    }

    private static WebApplication Build(RefreshTokenTransport transport, IRefreshTokenService? refreshTokens = null)
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
        builder.Services.AddAuthentication();
        builder.Services.AddJwtEndpoints<ExternalJwtUser, ExternalJwtDb>(options =>
        {
            options.Issuer = "https://jwt.example";
            options.Audience = "https://jwt.example";
            options.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
            options.RefreshTokenTransport = transport;
        });
        builder.Services.AddExternalAuthEndpoints<ExternalJwtUser>();
        if (refreshTokens is not null)
        {
            builder.Services.AddScoped(_ => refreshTokens);
        }

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
