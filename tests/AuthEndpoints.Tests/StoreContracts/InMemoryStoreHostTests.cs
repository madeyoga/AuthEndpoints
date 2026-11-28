using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints.EmailCode;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.Tests.StoreContracts;

/// <summary>
/// #410: the endpoints run over any store. Here only Identity's user store is EF Core; email codes and refresh tokens live
/// in the in-memory stores, with no AuthEndpoints.EntityFrameworkCore registration.
/// </summary>
public sealed class InMemoryStoreHostTests : IAsyncLifetime
{
    private const string Email = "memory@test.local";

    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly InMemoryEmailCodeStore _emailCodes = new();
    private readonly InMemoryRefreshTokenStore _refreshTokens = new();
    private readonly CapturingEmailSender _mail = new();
    private WebApplication _app = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        await _connection.OpenAsync();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<IdentityUsersDbContext>(options => options.UseSqlite(_connection));
        builder.Services.AddSingleton<IEmailSender<TestAppUser>>(_mail);
        builder.Services.AddSingleton<IEmailCodeSender<TestAppUser>>(_mail);
        builder.Services.AddSingleton<IEmailCodeStore>(_emailCodes);
        builder.Services.AddSingleton<IRefreshTokenStore>(_refreshTokens);
        var auth = builder.Services.AddAuthEndpoints<TestAppUser>()
            .AddPassword()
            .AddEmailCode()
            .AddJwt(jwt =>
            {
                jwt.Issuer = "https://issuer.test";
                jwt.Audience = "https://audience.test";
                jwt.SigningOptions.SymmetricKey = new string('k', 64);
                jwt.RefreshTokenTransport = RefreshTokenTransport.Body;
            });
        // Identity's own EF store for users only.
        auth.Identity.AddEntityFrameworkStores<IdentityUsersDbContext>();

        _app = builder.Build();
        _app.UseAuthEndpoints();
        _app.MapAuthEndpoints<TestAppUser>("/auth", AuthEndpointsSession.Jwt);
        await _app.StartAsync();
        _client = _app.GetTestClient();

        using var scope = _app.Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<IdentityUsersDbContext>().Database.EnsureCreatedAsync();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
        var created = await users.CreateAsync(
            new TestAppUser { UserName = Email, Email = Email, EmailConfirmed = true },
            TestHelpers.DefaultPassword);
        Assert.True(created.Succeeded);
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
        await _connection.DisposeAsync();
    }

    [Fact]
    public void TheStoresAreTheInMemoryOnes()
    {
        using var scope = _app.Services.CreateScope();
        Assert.Same(_emailCodes, scope.ServiceProvider.GetRequiredService<IEmailCodeStore>());
        Assert.Same(_refreshTokens, scope.ServiceProvider.GetRequiredService<IRefreshTokenStore>());
    }

    [Fact]
    public async Task Jwt_CreateRefreshAndReuseDetection_WorkOverTheInMemoryStore()
    {
        var created = await PostAsync("/auth/create", new { email = Email, password = TestHelpers.DefaultPassword });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var first = await RefreshTokenAsync(created);

        var rotated = await PostAsync("/auth/refresh", new { refreshToken = first });
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        var second = await RefreshTokenAsync(rotated);

        // Replaying the rotated token revokes the family, so its successor fails too.
        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync("/auth/refresh", new { refreshToken = first })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync("/auth/refresh", new { refreshToken = second })).StatusCode);
    }

    [Fact]
    public async Task EmailCode_SendVerifyAndSingleUse_WorkOverTheInMemoryStore()
    {
        Assert.Equal(HttpStatusCode.OK, (await PostAsync("/auth/emailCode/send", new { email = Email })).StatusCode);
        var code = Assert.Single(_mail.Snapshot(), mail => mail.Email == Email && mail.Kind == "email-code").Body;
        Assert.Single(_emailCodes.Snapshot());
        Assert.DoesNotContain(code, _emailCodes.Snapshot()[0].CodeHash, StringComparison.Ordinal);

        var verified = await PostAsync("/auth/emailCode/verify", new { email = Email, code });
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        Assert.False(string.IsNullOrEmpty(await RefreshTokenAsync(verified)));
        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync("/auth/emailCode/verify", new { email = Email, code })).StatusCode);
    }

    private Task<HttpResponseMessage> PostAsync(string path, object body) => _client.PostAsJsonAsync(path, body);

    private static async Task<string> RefreshTokenAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("refreshToken").GetString()!;
    }

    private sealed class IdentityUsersDbContext(DbContextOptions<IdentityUsersDbContext> options)
        : Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext<TestAppUser>(options);
}
