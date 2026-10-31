using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.External.OAuth.Tests;

public sealed class ProviderListTests
{
    [Fact]
    public async Task Zero_providers_lists_no_providers_and_no_logins()
    {
        await using var host = await ProviderHost.StartAsync([]);

        var providers = await host.Client.GetFromJsonAsync<ProviderItem[]>("/auth/external/providers");
        Assert.Empty(providers!);

        await host.CreateUserAsync("zero@example.com", "Passw0rd");
        await host.SignInAsync("zero@example.com");
        var logins = await host.Client.GetAsync("/auth/external/logins");
        Assert.Equal(HttpStatusCode.OK, logins.StatusCode);
        Assert.Equal("[]", await logins.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task One_provider_is_listed_with_its_display_name()
    {
        await using var host = await ProviderHost.StartAsync([("Alpha", "Alpha Login")]);

        var providers = await host.Client.GetFromJsonAsync<ProviderItem[]>("/auth/external/providers");

        Assert.Equal([new ProviderItem("Alpha", "Alpha Login")], providers!);
    }

    [Fact]
    public async Task Several_providers_are_listed_in_registration_order_anonymously()
    {
        await using var host = await ProviderHost.StartAsync(
            [("Zeta", "Zeta"), ("Alpha", null), ("Mid", "Middle Co")]);

        var response = await host.Client.GetAsync("/auth/external/providers");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var providers = await response.Content.ReadFromJsonAsync<ProviderItem[]>();

        Assert.Equal(
            [new ProviderItem("Zeta", "Zeta"), new ProviderItem("Alpha", "Alpha"), new ProviderItem("Mid", "Middle Co")],
            providers!);
    }

    [Fact]
    public async Task Several_providers_list_logins_for_the_signed_in_user()
    {
        await using var host = await ProviderHost.StartAsync([("Alpha", null), ("Beta", null)]);
        await host.CreateUserAsync("many@example.com", "Passw0rd", ("Alpha", "a-1"), ("Beta", "b-1"));
        await host.SignInAsync("many@example.com");

        var logins = await host.Client.GetFromJsonAsync<LoginItem[]>("/auth/external/logins");

        Assert.Equal(["Alpha", "Beta"], logins!.Select(l => l.LoginProvider).Order().ToArray());
    }

    [Fact]
    public async Task Zero_providers_unlink_still_refuses_the_last_sign_in_method()
    {
        await using var host = await ProviderHost.StartAsync([]);
        await host.CreateUserAsync("last@example.com", password: null, ("Removed", "r-1"));
        await host.SignInAsync("last@example.com");
        await host.ReauthAsync();

        var response = await host.DeleteWithCsrfAsync("/auth/external/logins/Removed/r-1");

        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{response.StatusCode} {body}");
        Assert.Contains("last_signin_method", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Zero_providers_unlink_succeeds_when_a_password_remains()
    {
        await using var host = await ProviderHost.StartAsync([]);
        await host.CreateUserAsync("pw@example.com", "Passw0rd", ("Removed", "r-2"));
        await host.SignInAsync("pw@example.com");
        await host.ReauthAsync();

        var response = await host.DeleteWithCsrfAsync("/auth/external/logins/Removed/r-2");

        Assert.True(response.StatusCode == HttpStatusCode.NoContent, $"{response.StatusCode} {await response.Content.ReadAsStringAsync()}");
    }

    private sealed record ProviderItem(string Scheme, string DisplayName);

    private sealed record LoginItem(string LoginProvider, string ProviderKey, string? ProviderDisplayName);

    private sealed record CsrfBody(string Token);

    private sealed class ProviderHost : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly string _path;

        private ProviderHost(WebApplication app, string path)
        {
            _app = app;
            _path = path;
            Client = new HttpClient(new CookieHandler(app.GetTestServer().CreateHandler()))
            {
                BaseAddress = app.GetTestServer().BaseAddress,
            };
            Client.DefaultRequestHeaders.TryAddWithoutValidation(
                "Origin",
                Client.BaseAddress!.GetLeftPart(UriPartial.Authority));
        }

        public HttpClient Client { get; }

        public static async Task<ProviderHost> StartAsync((string Scheme, string? DisplayName)[] providers)
        {
            var path = Path.Combine(Path.GetTempPath(), $"ae-providers-{Guid.NewGuid():N}.sqlite");
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<OAuthDb>(options => options.UseSqlite($"Data Source={path};Pooling=False"));
            builder.Services
                .AddIdentity<OAuthUser, IdentityRole>(options =>
                {
                    options.Password.RequiredLength = 6;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequireUppercase = false;
                    options.Password.RequireLowercase = false;
                    options.Password.RequireDigit = false;
                    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                })
                .AddEntityFrameworkStores<OAuthDb>()
                .AddDefaultTokenProviders();
            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.Events.OnRedirectToLogin = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };
            });

            var external = builder.Services.AddExternalAuthEndpoints<OAuthUser>();
            var authentication = builder.Services.AddAuthentication();
            foreach (var (scheme, displayName) in providers)
            {
                authentication.AddScheme<AuthenticationSchemeOptions, NoopHandler>(scheme, displayName, _ => { });
                external.AddProvider(new ListedProvider(scheme));
            }

            builder.Services.AddAuthorization();
            builder.Services.AddAntiforgery();

            var app = builder.Build();
            using (var scope = app.Services.CreateScope())
            {
                await scope.ServiceProvider.GetRequiredService<OAuthDb>().Database.EnsureCreatedAsync();
            }

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseAntiforgery();
            app.MapGroup("/auth/external").MapExternalAccountEndpoints<OAuthUser>();

            app.MapPost("/test/user", async (NewUser body, UserManager<OAuthUser> users) =>
            {
                var user = new OAuthUser { UserName = body.Email, Email = body.Email, EmailConfirmed = true };
                var result = body.Password is null
                    ? await users.CreateAsync(user)
                    : await users.CreateAsync(user, body.Password);
                foreach (var login in body.Logins)
                {
                    result = await users.AddLoginAsync(user, new UserLoginInfo(login[0], login[1], login[0]));
                }

                return result.Succeeded ? Results.NoContent() : Results.BadRequest(result.Errors);
            });
            app.MapPost("/test/signin", async (string email, SignInManager<OAuthUser> signIn, UserManager<OAuthUser> users) =>
            {
                await signIn.SignInAsync((await users.FindByEmailAsync(email))!, isPersistent: false);
                return Results.NoContent();
            });
            app.MapPost("/test/reauth", async (HttpContext http) =>
            {
                var identity = new ClaimsIdentity(http.User.Claims.Append(new Claim("Reauth", "true")), AuthEndpointsConstants.ReAuthScheme);
                await http.SignInAsync(AuthEndpointsConstants.ReAuthScheme, new ClaimsPrincipal(identity));
                return Results.NoContent();
            });
            app.MapGet("/test/csrf", (HttpContext http, IAntiforgery antiforgery) =>
                Results.Ok(new { token = antiforgery.GetAndStoreTokens(http).RequestToken }));

            await app.StartAsync();
            return new ProviderHost(app, path);
        }

        public async Task CreateUserAsync(string email, string? password, params (string Provider, string Key)[] logins)
        {
            var response = await Client.PostAsJsonAsync("/test/user", new NewUser(
                email,
                password,
                logins.Select(l => new[] { l.Provider, l.Key }).ToArray()));
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        }

        public async Task SignInAsync(string email) =>
            Assert.Equal(HttpStatusCode.NoContent, (await Client.PostAsync($"/test/signin?email={Uri.EscapeDataString(email)}", null)).StatusCode);

        public async Task ReauthAsync() =>
            Assert.Equal(HttpStatusCode.NoContent, (await Client.PostAsync("/test/reauth", null)).StatusCode);

        public async Task<HttpResponseMessage> DeleteWithCsrfAsync(string path)
        {
            var csrf = await Client.GetFromJsonAsync<CsrfBody>("/test/csrf");
            var request = new HttpRequestMessage(HttpMethod.Delete, path);
            request.Headers.Add("RequestVerificationToken", csrf!.Token);
            return await Client.SendAsync(request);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _app.StopAsync();
            await _app.DisposeAsync();
            SqliteConnection.ClearAllPools();
            try
            {
                File.Delete(_path);
            }
            catch (IOException)
            {
            }
        }
    }

    private sealed record NewUser(string Email, string? Password, string[][] Logins);

    private sealed class ListedProvider(string scheme) : IExternalAuthProvider
    {
        public string Scheme => scheme;
        public string LoginPath => $"login/{scheme.ToLowerInvariant()}";
        public string CallbackPath => $"login/{scheme.ToLowerInvariant()}/callback";
        public string CallbackEndpointName => $"{scheme}LoginCallback";
    }

    private sealed class CookieHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        private readonly CookieContainer _cookies = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var header = _cookies.GetCookieHeader(request.RequestUri!);
            if (!string.IsNullOrEmpty(header))
            {
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
