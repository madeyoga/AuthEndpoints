using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace AuthEndpoints.OpenIddict.Tests;

internal sealed class TestDb(DbContextOptions<TestDb> options) : IdentityDbContext<IdentityUser>(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.UseAuthEndpointsOpenIddict<IdentityUser>();
    }

    // SQLite cannot compare DateTimeOffset values. Production providers do not need this.
    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
        => configurationBuilder.Properties<DateTimeOffset>().HaveConversion<DateTimeOffsetToBinaryConverter>();
}

internal sealed record RegisteredClient(string ClientId, string RedirectUri);

internal sealed record TokenPair(string AccessToken, string RefreshToken, JsonElement Body);

internal sealed record Pkce(string Verifier, string Challenge)
{
    public static Pkce Create()
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        return new Pkce(verifier, Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>An in-memory app with Identity cookies, the OAuth server, a consent API, and a protected <c>/api/me</c>.</summary>
internal sealed class OAuthTestHost : IAsyncDisposable
{
    public const string Issuer = "https://localhost/";
    public const string Audience = "https://localhost/api";
    public const string OtherResource = "https://other.example/api";
    public const string LoginUrl = "https://app.example/sign-in";
    public const string ConsentUrl = "https://app.example/oauth/consent";
    public const string Loopback = "http://127.0.0.1:9/callback";
    public const string SeededClientId = "seeded-spa";
    public const string SeededRedirect = "https://spa.example/callback";
    public const string CsrfHeader = "X-CSRF-TOKEN";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly string _path;
    private int _address;

    private OAuthTestHost(WebApplication app, string path)
    {
        App = app;
        _path = path;
    }

    public WebApplication App { get; }

    public IServiceProvider Services => App.Services;

    public static async Task<OAuthTestHost> StartAsync(
        Action<OAuthServerOptions>? configure = null,
        Action<IServiceCollection>? services = null,
        Action<WebApplication>? map = null)
    {
        var path = Path.Combine(Path.GetTempPath(), $"ae-openiddict-{Guid.NewGuid():N}.sqlite");
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddDbContext<TestDb>(options => options.UseSqlite($"Data Source={path};Pooling=False"));
        builder.Services.AddIdentity<IdentityUser, IdentityRole>(identity =>
            {
                identity.Password.RequiredLength = 6;
                identity.Password.RequireDigit = false;
                identity.Password.RequireLowercase = false;
                identity.Password.RequireUppercase = false;
                identity.Password.RequireNonAlphanumeric = false;
            })
            .AddEntityFrameworkStores<TestDb>()
            .AddDefaultTokenProviders();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
        });
        builder.Services.AddAntiforgery(options => options.HeaderName = CsrfHeader);
        builder.Services.AddAuthorization(options => options.AddPolicy("api", policy => policy
            .AddAuthenticationSchemes(OAuthServerServiceCollectionExtensions.ValidationScheme)
            .RequireAuthenticatedUser()));

        builder.Services.AddAuthEndpointsOpenIddict<IdentityUser, TestDb>(options =>
        {
            options.Issuer = new Uri(Issuer);
            options.Audience = Audience;
            options.AdditionalResources.Add(OtherResource);
            options.Scopes.Add("api");
            options.Scopes.Add("profile");
            options.DefaultScopes.Add("api");
            options.LoginUrl = LoginUrl;
            options.ConsentUrl = ConsentUrl;
            options.Certificates.UseEphemeralKeys = true;
            options.CleanupInterval = TimeSpan.Zero;
            options.DynamicRegistration.Enabled = true;
            options.DynamicRegistration.PermitsPerMinute = 1000;
            options.ProtectedResource.Enabled = true;
            options.ProtectedResource.ResourceName = "Test API";
            options.ProtectedResource.ChallengePaths.Add("/api");
            var seeded = new OAuthClientDefinition { ClientId = SeededClientId, DisplayName = "Seeded SPA" };
            seeded.RedirectUris.Add(SeededRedirect);
            options.Clients.Add(seeded);
            configure?.Invoke(options);
        });
        services?.Invoke(builder.Services);

        var app = builder.Build();
        app.UseOAuthResourceChallenge();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();
        app.MapAuthEndpointsOpenIddict();
        app.MapOAuthConsentEndpoints();
        app.MapOAuthDeveloperAppEndpoints();
        app.MapGet("/api/me", (HttpContext http) => Results.Ok(new
        {
            sub = http.User.FindFirst(OpenIddictConstants.Claims.Subject)?.Value,
            scopes = http.User.GetScopes().ToArray(),
            claims = http.User.Claims.Select(claim => claim.Type).Distinct().ToArray(),
        })).RequireAuthorization("api");
        app.MapPost("/test/2fa/start", async (string email, UserManager<IdentityUser> users, SignInManager<IdentityUser> signIn) =>
        {
            var user = new IdentityUser { UserName = email, Email = email, EmailConfirmed = true, TwoFactorEnabled = true };
            var created = await users.CreateAsync(user, "Passw0rd1");
            if (!created.Succeeded)
            {
                return Results.BadRequest(created.Errors);
            }

            var result = await signIn.PasswordSignInAsync(email, "Passw0rd1", isPersistent: false, lockoutOnFailure: false);
            return Results.Ok(new { id = user.Id, requiresTwoFactor = result.RequiresTwoFactor });
        }).DisableAntiforgery();
        app.MapPost("/test/2fa/finish", async (UserManager<IdentityUser> users, SignInManager<IdentityUser> signIn) =>
        {
            var user = await signIn.GetTwoFactorAuthenticationUserAsync();
            if (user is null)
            {
                return Results.BadRequest();
            }

            var code = await users.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            var result = await signIn.TwoFactorSignInAsync(TokenOptions.DefaultEmailProvider, code, false, false);
            return result.Succeeded ? Results.NoContent() : Results.BadRequest();
        }).DisableAntiforgery();
        app.MapPost("/test/external-only", async (HttpContext http) =>
        {
            var identity = new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, "github-123")],
                IdentityConstants.ExternalScheme);
            await http.SignInAsync(IdentityConstants.ExternalScheme, new System.Security.Claims.ClaimsPrincipal(identity));
            return Results.NoContent();
        }).DisableAntiforgery();
        app.MapPost("/test/signin", async (string email, UserManager<IdentityUser> users, SignInManager<IdentityUser> signIn) =>
        {
            var user = await users.FindByEmailAsync(email);
            if (user is null)
            {
                user = new IdentityUser { UserName = email, Email = email, EmailConfirmed = true };
                var created = await users.CreateAsync(user);
                if (!created.Succeeded)
                {
                    return Results.BadRequest(created.Errors);
                }
            }

            await signIn.SignInAsync(user, isPersistent: false);
            return Results.Ok(new { id = user.Id });
        }).DisableAntiforgery();
        app.MapGet("/test/csrf", (HttpContext http, IAntiforgery antiforgery)
            => Results.Ok(new { token = antiforgery.GetAndStoreTokens(http).RequestToken }));
        map?.Invoke(app);

        await using (var scope = app.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<TestDb>().Database.EnsureCreatedAsync();
        }

        await app.Services.SeedOAuthClientsAsync();
        await app.StartAsync();
        return new OAuthTestHost(app, path);
    }

    /// <summary>A client with its own cookie jar and its own remote address.</summary>
    public HttpClient Client(string baseAddress = "https://localhost/", bool cookies = true)
    {
        var server = App.GetTestServer();
        var n = Interlocked.Increment(ref _address);
        var address = new IPAddress([10, 0, (byte)(n / 250), (byte)(n % 250 + 1)]);
        HttpMessageHandler handler = new AddressHandler(server, address);
        if (cookies)
        {
            handler = new CookieHandler(handler);
        }

        return new HttpClient(handler) { BaseAddress = new Uri(baseAddress) };
    }

    public async Task<(HttpClient Client, string UserId)> UserAsync(string label)
    {
        var client = Client();
        var response = await client.PostAsync($"/test/signin?email={label}-{Guid.NewGuid():N}@example.test", null);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return (client, body.GetProperty("id").GetString()!);
    }

    public async Task<RegisteredClient> RegisterAsync(string name = "Test client", string redirect = Loopback, string scope = "api")
    {
        using var anon = Client(cookies: false);
        var response = await anon.PostAsJsonAsync("/connect/register", new
        {
            redirect_uris = new[] { redirect },
            token_endpoint_auth_method = "none",
            grant_types = new[] { "authorization_code", "refresh_token" },
            response_types = new[] { "code" },
            client_name = name,
            scope,
        });
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.Created, text);
        var json = JsonSerializer.Deserialize<JsonElement>(text);
        return new RegisteredClient(json.GetProperty("client_id").GetString()!, redirect);
    }

    public static string AuthorizeUrl(
        string clientId,
        string redirect,
        string? challenge,
        string state = "st",
        string? method = "S256",
        string? scope = "api",
        string? resource = null,
        string? prompt = null)
    {
        var query = new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = redirect,
            ["response_type"] = "code",
            ["state"] = state,
        };
        if (scope is not null)
        {
            query["scope"] = scope;
        }

        if (resource is not null)
        {
            query["resource"] = resource;
        }

        if (challenge is not null)
        {
            query["code_challenge"] = challenge;
        }

        if (method is not null)
        {
            query["code_challenge_method"] = method;
        }

        if (prompt is not null)
        {
            query["prompt"] = prompt;
        }

        return QueryHelpers.AddQueryString("/connect/authorize", query);
    }

    /// <summary>Runs authorize as a signed-in user and returns the pending consent id.</summary>
    public static async Task<Guid> StartAsync(
        HttpClient user, string clientId, string redirect, string challenge, string state = "st", string? scope = "api", string? resource = null)
    {
        var response = await user.GetAsync(AuthorizeUrl(clientId, redirect, challenge, state, scope: scope, resource: resource));
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.Redirect, $"authorize returned {(int)response.StatusCode} {body}");
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(ConsentUrl + "?request=", location, StringComparison.Ordinal);
        return Guid.Parse(Query(location)["request"]);
    }

    public static async Task<HttpResponseMessage> PostConsentAsync(HttpClient user, Guid id, string action)
    {
        var csrf = await user.GetFromJsonAsync<JsonElement>("/test/csrf");
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/oauth/requests/{id}/{action}");
        request.Headers.Add(CsrfHeader, csrf.GetProperty("token").GetString());
        return await user.SendAsync(request);
    }

    /// <summary>Approves and returns the redirect query (code, state, iss).</summary>
    public static async Task<Dictionary<string, string>> ApproveAsync(HttpClient user, Guid id)
    {
        var response = await PostConsentAsync(user, id, "approve");
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, text);
        var redirect = JsonSerializer.Deserialize<OAuthConsentRedirect>(text, Json)!.RedirectUrl;
        return Query(redirect);
    }

    public async Task<(RegisteredClient Client, TokenPair Tokens)> IssueAsync(HttpClient user, string? resource = null, string name = "Issued")
    {
        var client = await RegisterAsync(name);
        var pkce = Pkce.Create();
        var id = await StartAsync(user, client.ClientId, client.RedirectUri, pkce.Challenge, resource: resource);
        var approved = await ApproveAsync(user, id);
        using var anon = Client(cookies: false);
        var tokens = await ReadTokenAsync(await TokenAsync(anon, CodeGrant(client, approved["code"], pkce.Verifier)));
        return (client, tokens);
    }

    public static Dictionary<string, string> CodeGrant(RegisteredClient client, string code, string? verifier) => CodeGrant(client.ClientId, client.RedirectUri, code, verifier);

    public static Dictionary<string, string> CodeGrant(string clientId, string redirect, string code, string? verifier)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirect,
            ["client_id"] = clientId,
        };
        if (verifier is not null)
        {
            form["code_verifier"] = verifier;
        }

        return form;
    }

    public static Dictionary<string, string> RefreshGrant(string clientId, string refreshToken) => new()
    {
        ["grant_type"] = "refresh_token",
        ["refresh_token"] = refreshToken,
        ["client_id"] = clientId,
    };

    public static Task<HttpResponseMessage> TokenAsync(HttpClient anon, Dictionary<string, string> form)
        => anon.PostAsync("/connect/token", new FormUrlEncodedContent(form));

    public static async Task<TokenPair> ReadTokenAsync(HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, text);
        var json = JsonSerializer.Deserialize<JsonElement>(text);
        return new TokenPair(json.GetProperty("access_token").GetString()!, json.GetProperty("refresh_token").GetString()!, json);
    }

    public static async Task<string> ErrorAsync(HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode} {text}");
        return JsonSerializer.Deserialize<JsonElement>(text).GetProperty("error").GetString()!;
    }

    public async Task<HttpResponseMessage> CallApiAsync(string accessToken)
    {
        using var api = Client(cookies: false);
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await api.GetAsync("/api/me");
    }

    public async Task<string> SubjectAsync(string accessToken)
    {
        var response = await CallApiAsync(accessToken);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode} {text} {response.Headers.WwwAuthenticate}");
        return JsonSerializer.Deserialize<JsonElement>(text).GetProperty("sub").GetString()!;
    }

    public static Dictionary<string, string> Query(string uri)
    {
        var index = uri.IndexOf('?', StringComparison.Ordinal);
        var query = index < 0 ? uri : uri[index..];
        return QueryHelpers.ParseQuery(query).ToDictionary(pair => pair.Key, pair => pair.Value.ToString(), StringComparer.Ordinal);
    }

    public async ValueTask DisposeAsync()
    {
        await App.StopAsync();
        await App.DisposeAsync();
        try
        {
            File.Delete(_path);
        }
        catch (IOException)
        {
        }
    }

    private sealed class AddressHandler(TestServer server, IPAddress address) : DelegatingHandler(server.CreateHandler(context => context.Connection.RemoteIpAddress = address));

    private sealed class CookieHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        private readonly CookieContainer _cookies = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var header = _cookies.GetCookieHeader(request.RequestUri!);
            if (!string.IsNullOrEmpty(header))
            {
                request.Headers.Remove("Cookie");
                request.Headers.Add("Cookie", header);
            }

            var response = await base.SendAsync(request, cancellationToken);
            if (response.Headers.TryGetValues("Set-Cookie", out var values))
            {
                foreach (var value in values)
                {
                    _cookies.SetCookies(request.RequestUri!, value);
                }
            }

            return response;
        }
    }
}
