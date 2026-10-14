using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using AuthEndpoints.EmailCode;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.External.OAuth.Tests;

internal sealed class ExternalHost : IAsyncDisposable
{
    public static readonly NamedProvider CookieProvider = new("CookieScheme", "login/cookie", "login/cookie/callback", "CookieCallback");
    public static readonly NamedProvider BearerProvider = new("BearerScheme", "login/bearer", "login/bearer/callback", "BearerCallback");
    public static readonly NamedProvider JwtProvider = new("JwtScheme", "login/jwt", "login/jwt/callback", "JwtCallback");
    public static readonly NamedProvider SpyProvider = new("SpyScheme", "login/spy", "login/spy/callback", "SpyCallback");
    public static readonly NamedProvider LegacyProvider = new("LegacyScheme", "login/legacy", "login/legacy/callback", "LegacyCallback");
    public static readonly NamedProvider SessionProvider = new("SessionScheme", "login/session", "login/session/callback", "SessionCallback");

    private readonly string _path;
    private readonly JarClient _client;

    private ExternalHost(WebApplication app, string path)
    {
        App = app;
        _path = path;
        _client = new JarClient(app);
    }

    public WebApplication App { get; }

    public static WebApplicationBuilder CreateBuilder(Action<IServiceCollection>? configure = null)
    {
        var path = Path.Combine(Path.GetTempPath(), $"ae-external-flow-{Guid.NewGuid():N}.sqlite");
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<FlowDb>(options => options.UseSqlite($"Data Source={path};Pooling=False"));
        builder.Services.AddIdentityApiEndpoints<FlowUser>(identity =>
            {
                identity.SignIn.RequireConfirmedAccount = false;
                identity.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                identity.Password.RequireDigit = false;
                identity.Password.RequireLowercase = false;
                identity.Password.RequireUppercase = false;
                identity.Password.RequireNonAlphanumeric = false;
                identity.Password.RequiredLength = 6;
            })
            .AddEntityFrameworkStores<FlowDb>()
            .AddDefaultTokenProviders();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
        });
        builder.Services.AddExternalAuthEndpoints<FlowUser>(options =>
        {
            options.DefaultReturnUrl = "/";
            options.ErrorPath = "/auth/external/error";
        });
        builder.Services.AddSingleton<IExternalAuthProvider>(CookieProvider);
        builder.Services.AddSingleton<IExternalAuthProvider>(BearerProvider);
        builder.Services.AddSingleton<IExternalAuthProvider>(JwtProvider);
        builder.Services.AddSingleton<IExternalAuthProvider>(SpyProvider);
        builder.Services.AddSingleton<IExternalAuthProvider>(LegacyProvider);
        builder.Services.AddSingleton<IExternalAuthProvider>(SessionProvider);
        builder.Services.AddJwtEndpoints<FlowUser, FlowDb>(jwt =>
        {
            jwt.Issuer = "https://jwt.example";
            jwt.Audience = "https://jwt.example";
            jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
        });
        builder.Services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, NoopHandler>(CookieProvider.Scheme, _ => { })
            .AddScheme<AuthenticationSchemeOptions, NoopHandler>(BearerProvider.Scheme, _ => { })
            .AddScheme<AuthenticationSchemeOptions, NoopHandler>(JwtProvider.Scheme, _ => { })
            .AddScheme<AuthenticationSchemeOptions, NoopHandler>(SpyProvider.Scheme, _ => { })
            .AddScheme<AuthenticationSchemeOptions, NoopHandler>(LegacyProvider.Scheme, _ => { })
            .AddScheme<AuthenticationSchemeOptions, NoopHandler>(SessionProvider.Scheme, _ => { });
        configure?.Invoke(builder.Services);
        builder.Services.AddSingleton(new FlowDbPath(path));
        return builder;
    }

    public static async Task<ExternalHost> StartAsync(Action<WebApplication> map, Action<IServiceCollection>? configure = null)
    {
        var builder = CreateBuilder(configure);
        var app = builder.Build();
        var path = app.Services.GetRequiredService<FlowDbPath>().Path;
        using (var scope = app.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<FlowDb>().Database.EnsureCreatedAsync();
        }

        app.UseAuthentication();
        app.UseAuthorization();
        map(app);
        app.MapPost("/test/external-cookie", async (ExternalCookie body, HttpContext http) =>
        {
            var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, body.Key) };
            if (!string.IsNullOrEmpty(body.Email))
            {
                claims.Add(new Claim(ClaimTypes.Email, body.Email));
                claims.Add(new Claim(ExternalEmailClaims.EmailVerifiedClaimType, "true"));
            }

            var identity = new ClaimsIdentity(claims, IdentityConstants.ExternalScheme);
            var properties = new AuthenticationProperties();
            properties.Items["LoginProvider"] = body.Provider;
            await http.SignInAsync(IdentityConstants.ExternalScheme, new ClaimsPrincipal(identity), properties);
            return Results.NoContent();
        });
        await app.StartAsync();
        return new ExternalHost(app, path);
    }

    public async Task<(HttpResponseMessage Status, string Body)> CallbackAsync(
        string prefix,
        string provider,
        string? email,
        string key,
        string returnUrl = "/done")
    {
        var planted = await _client.PostAsJsonAsync("/test/external-cookie", new { provider, key, email });
        Assert.Equal(HttpStatusCode.NoContent, planted.StatusCode);
        var callback = await _client.GetAsync($"{prefix}/{LoginPath(provider)}/callback?returnUrl={Uri.EscapeDataString(returnUrl)}");
        return (callback, await callback.Content.ReadAsStringAsync());
    }

    public async ValueTask DisposeAsync()
    {
        _client.Dispose();
        await App.StopAsync();
        await App.DisposeAsync();
        SqliteConnection.ClearAllPools();
        TryDelete(_path);
    }

    private static string LoginPath(string scheme) => scheme switch
    {
        "CookieScheme" => "login/cookie",
        "BearerScheme" => "login/bearer",
        "JwtScheme" => "login/jwt",
        "SpyScheme" => "login/spy",
        "LegacyScheme" => "login/legacy",
        "SessionScheme" => "login/session",
        _ => throw new ArgumentOutOfRangeException(nameof(scheme)),
    };

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
    }

    private sealed record FlowDbPath(string Path);

    private sealed record ExternalCookie(string Provider, string Key, string? Email);

    private sealed class NoopHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public NoopHandler(
            Microsoft.Extensions.Options.IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            System.Text.Encodings.Web.UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
            Task.FromResult(AuthenticateResult.NoResult());
    }
}

internal sealed class NamedProvider : IExternalAuthProvider
{
    public NamedProvider(string scheme, string loginPath, string callbackPath, string callbackEndpointName)
    {
        Scheme = scheme;
        LoginPath = loginPath;
        CallbackPath = callbackPath;
        CallbackEndpointName = callbackEndpointName;
    }

    public string Scheme { get; }
    public string LoginPath { get; }
    public string CallbackPath { get; }
    public string CallbackEndpointName { get; }
}

internal sealed class FlowDb : IdentityDbContext<FlowUser>
{
    public FlowDb(DbContextOptions<FlowDb> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.UseEmailCodes();
        builder.UseRefreshToken();
    }
}

internal sealed class FlowUser : IdentityUser;

internal sealed class JarClient : IDisposable
{
    private readonly HttpClient _client;
    private readonly List<string> _cookies = new();

    public JarClient(WebApplication app)
    {
        _client = app.GetTestClient();
        _client.DefaultRequestHeaders.TryAddWithoutValidation(
            "Origin",
            _client.BaseAddress!.GetLeftPart(UriPartial.Authority));
    }

    public void Dispose() => _client.Dispose();

    public Task<HttpResponseMessage> GetAsync(string path) => SendAsync(HttpMethod.Get, path, null);

    public Task<HttpResponseMessage> PostAsync(string path) => SendAsync(HttpMethod.Post, path, null);

    public Task<HttpResponseMessage> PostAsJsonAsync<T>(string path, T body) =>
        SendAsync(HttpMethod.Post, path, JsonContent.Create(body));

    public Task<HttpResponseMessage> PostAsJsonAsync<T>(string path, T body, string csrf) =>
        SendAsync(HttpMethod.Post, path, JsonContent.Create(body), csrf);

    public Task<HttpResponseMessage> DeleteAsync(string path, string? csrf = null) =>
        SendAsync(HttpMethod.Delete, path, null, csrf);

    public async Task<string> CsrfAsync(string path)
    {
        var response = await GetAsync(path);
        response.EnsureSuccessStatusCode();
        using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        return doc.RootElement.TryGetProperty("csrfToken", out var token)
            ? token.GetString()!
            : doc.RootElement.GetProperty("token").GetString()!;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, HttpContent? content, string? csrf = null)
    {
        var request = new HttpRequestMessage(method, path) { Content = content };
        if (_cookies.Count > 0)
        {
            request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", _cookies));
        }

        if (!string.IsNullOrEmpty(csrf))
        {
            request.Headers.TryAddWithoutValidation("RequestVerificationToken", csrf);
        }

        var response = await _client.SendAsync(request);
        Capture(response);
        return response;
    }

    private void Capture(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return;
        }

        foreach (var value in values)
        {
            var pair = value.Split(';', 2)[0];
            var name = pair.Split('=', 2)[0];
            _cookies.RemoveAll(cookie => cookie.StartsWith(name + "=", StringComparison.Ordinal));
            if (!pair.EndsWith("=", StringComparison.Ordinal))
            {
                _cookies.Add(pair);
            }
        }
    }
}
