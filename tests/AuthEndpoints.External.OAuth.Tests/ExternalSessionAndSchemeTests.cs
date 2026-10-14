using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using AuthEndpoints;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.External.OAuth.Tests;

public class ExternalSessionAndSchemeTests
{
    [Fact]
    public async Task Three_sessions_match_the_documented_callback_responses()
    {
        await using var host = await ExternalHost.StartAsync(app =>
        {
            app.MapGroup("/cookie").MapExternalAuthProvider<FlowUser>(ExternalHost.CookieProvider, AuthEndpointsSession.Cookie);
            app.MapGroup("/bearer").MapExternalAuthProvider<FlowUser>(ExternalHost.BearerProvider, AuthEndpointsSession.IdentityBearer);
            app.MapGroup("/jwt").MapExternalAuthProvider<FlowUser>(ExternalHost.JwtProvider, AuthEndpointsSession.Jwt);
        });

        var cookie = await host.CallbackAsync("/cookie", ExternalHost.CookieProvider.Scheme, "cookie@example.com", "cookie-key");
        Assert.Equal(HttpStatusCode.Redirect, cookie.Status.StatusCode);
        Assert.Equal("/done", cookie.Status.Headers.Location?.ToString());
        Assert.Contains(cookie.Status.Headers, header =>
            header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase)
            && header.Value.Any(value => value.Contains(".AspNetCore.Identity.Application", StringComparison.Ordinal)));

        var bearer = await host.CallbackAsync("/bearer", ExternalHost.BearerProvider.Scheme, "bearer@example.com", "bearer-key");
        Assert.Equal(HttpStatusCode.OK, bearer.Status.StatusCode);
        Assert.Null(bearer.Status.Headers.Location);
        using (var body = JsonDocument.Parse(bearer.Body))
        {
            Assert.False(string.IsNullOrWhiteSpace(body.RootElement.GetProperty("accessToken").GetString()));
        }

        var jwt = await host.CallbackAsync("/jwt", ExternalHost.JwtProvider.Scheme, "jwt@example.com", "jwt-key");
        Assert.Equal(HttpStatusCode.Redirect, jwt.Status.StatusCode);
        var location = jwt.Status.Headers.Location?.ToString() ?? "";
        Assert.Equal("/done", location);
        Assert.DoesNotContain("accessToken", location, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(jwt.Status.Headers, header =>
            header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase)
            && header.Value.Any(value => value.Contains("AuthEndpoints.Jwt.RefreshToken", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task External_sign_in_skips_two_factor()
    {
        await using var host = await ExternalHost.StartAsync(app =>
            app.MapGroup("/cookie").MapExternalAuthProvider<FlowUser>(ExternalHost.CookieProvider, AuthEndpointsSession.Cookie));

        var created = await host.CallbackAsync("/cookie", ExternalHost.CookieProvider.Scheme, "factor@example.com", "factor-key");
        Assert.Equal(HttpStatusCode.Redirect, created.Status.StatusCode);

        using (var scope = host.App.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<FlowUser>>();
            var user = await users.FindByEmailAsync("factor@example.com");
            Assert.NotNull(user);
            Assert.True((await users.SetTwoFactorEnabledAsync(user!, true)).Succeeded);
        }

        var again = await host.CallbackAsync("/cookie", ExternalHost.CookieProvider.Scheme, "factor@example.com", "factor-key");
        var body = again.Body;
        Assert.Equal(HttpStatusCode.Redirect, again.Status.StatusCode);
        Assert.DoesNotContain("RequiresTwoFactor", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Spy_completer_is_not_called_when_provision_fails()
    {
        SpyCompleter.Calls = 0;
        await using var host = await ExternalHost.StartAsync(
            app => app.MapGroup("/spy").MapExternalAuthProvider<FlowUser>(ExternalHost.SpyProvider, "Spy"),
            services => services.AddSignInCompleter<FlowUser, SpyCompleter>("Spy"));

        var failed = await host.CallbackAsync("/spy", ExternalHost.SpyProvider.Scheme, email: null, "spy-key");
        Assert.Equal(HttpStatusCode.Redirect, failed.Status.StatusCode);
        Assert.Contains("email_missing", failed.Status.Headers.Location?.OriginalString, StringComparison.Ordinal);
        Assert.Equal(0, SpyCompleter.Calls);
    }

    [Fact]
    public async Task Explicit_legacy_completer_wins_until_a_session_is_passed()
    {
        await using var host = await ExternalHost.StartAsync(app =>
        {
            app.MapGroup("/legacy").MapExternalAuthProvider<FlowUser>(ExternalHost.LegacyProvider);
            app.MapGroup("/session").MapExternalAuthProvider<FlowUser>(ExternalHost.SessionProvider, AuthEndpointsSession.Cookie);
        }, services => services.AddExternalAuthEndpoints<FlowUser>().AddCompleter<LegacyMarkerCompleter>());

        var legacy = await host.CallbackAsync("/legacy", ExternalHost.LegacyProvider.Scheme, "legacy@example.com", "legacy-key");
        Assert.Equal(HttpStatusCode.OK, legacy.Status.StatusCode);
        Assert.Equal("legacy-completer", legacy.Body);

        var session = await host.CallbackAsync("/session", ExternalHost.SessionProvider.Scheme, "session@example.com", "session-key");
        Assert.Equal(HttpStatusCode.Redirect, session.Status.StatusCode);
        Assert.NotEqual("legacy-completer", session.Body);
    }

    [Fact]
    public async Task Jwt_body_transport_throws_at_map_time()
    {
        var builder = ExternalHost.CreateBuilder(services =>
            services.Configure<JwtSessionOptions>(options => options.RefreshTokenTransport = RefreshTokenTransport.Body));
        await using var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<FlowDb>().Database.EnsureCreatedAsync();
        }

        var ex = Assert.Throws<InvalidOperationException>(() =>
            app.MapGroup("/jwt").MapExternalAuthProvider<FlowUser>(ExternalHost.JwtProvider, AuthEndpointsSession.Jwt));
        Assert.Equal(JwtExternalBodyTransportValidator.Message, ex.Message);

        using var check = app.Services.CreateScope();
        Assert.Equal(0, await check.ServiceProvider.GetRequiredService<FlowDb>().Set<RefreshToken>().CountAsync());
    }

    [Fact]
    public void Map_without_AddExternalAuthEndpoints_names_the_fix()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseTestServer();
        using var app = builder.Build();
        var ex = Assert.Throws<InvalidOperationException>(() => app.MapExternalAuthEndpoints<FlowUser>());
        Assert.Contains("AddExternalAuthEndpoints", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task List_and_link_ignore_a_custom_default_scheme()
    {
        var builder = ExternalHost.CreateBuilder();
        builder.Services.AddAuthentication()
            .AddCookie("Custom");
        builder.Services.Configure<AuthenticationOptions>(options =>
        {
            options.DefaultAuthenticateScheme = "Custom";
            options.DefaultChallengeScheme = "Custom";
        });
        await using var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<FlowDb>().Database.EnsureCreatedAsync();
        }

        app.UseAuthentication();
        app.UseAuthorization();
        var external = app.MapGroup("/auth/external");
        external.MapExternalAccountEndpoints<FlowUser>();
        app.MapPost("/test/user", async (string email, UserManager<FlowUser> users) =>
        {
            var user = new FlowUser { UserName = email, Email = email, EmailConfirmed = true };
            var result = await users.CreateAsync(user, "Passw0rd");
            return result.Succeeded ? Results.Ok() : Results.BadRequest();
        });
        app.MapPost("/test/custom", async (string email, UserManager<FlowUser> users, IUserClaimsPrincipalFactory<FlowUser> factory, HttpContext http) =>
        {
            var user = await users.FindByEmailAsync(email);
            var principal = await factory.CreateAsync(user!);
            var identity = new ClaimsIdentity(principal.Claims, "Custom");
            await http.SignInAsync("Custom", new ClaimsPrincipal(identity));
            return Results.NoContent();
        });
        app.MapPost("/test/app", async (string email, SignInManager<FlowUser> signIn, UserManager<FlowUser> users) =>
        {
            var user = await users.FindByEmailAsync(email);
            await signIn.SignInAsync(user!, isPersistent: false);
            return Results.NoContent();
        });
        await app.StartAsync();

        var list = FindEndpoint(app, "GET /auth/external/logins");
        var link = FindEndpoint(app, "GET /auth/external/link/CookieScheme");
        var callback = FindEndpoint(app, "GET /auth/external/link/CookieScheme/callback");
        foreach (var endpoint in new[] { list, link, callback })
        {
            var schemes = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>().Single().AuthenticationSchemes!;
            Assert.Contains(IdentityConstants.ApplicationScheme, schemes, StringComparison.Ordinal);
            Assert.DoesNotContain("Custom", schemes.Split(','), StringComparer.Ordinal);
        }

        var client = new JarClient(app);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/test/user?email=scheme@example.com")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/test/custom?email=scheme@example.com")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/auth/external/logins")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/test/app?email=scheme@example.com")).StatusCode);
        var listed = await client.GetAsync("/auth/external/logins");
        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
    }

    private static Endpoint FindEndpoint(WebApplication app, string route)
    {
        return ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(source => source.Endpoints)
            .Select(endpoint => (Endpoint)endpoint)
            .Single(endpoint =>
            {
                var method = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.SingleOrDefault();
                var pattern = (endpoint as RouteEndpoint)?.RoutePattern.RawText;
                return $"{method} {pattern}" == route;
            });
    }

    private sealed class SpyCompleter : ISignInCompleter<FlowUser>
    {
        public static int Calls;

        public Task<IResult> CompleteAsync(
            HttpContext httpContext,
            FlowUser user,
            SignInCompletionContext context,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult<IResult>(Results.Text("spy"));
        }
    }

    private sealed class LegacyMarkerCompleter : IExternalLoginCompleter<FlowUser>
    {
        public Task<IResult> CompleteAsync(
            HttpContext httpContext,
            FlowUser user,
            ExternalLoginInfo info,
            string? returnUrl,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IResult>(Results.Text("legacy-completer"));
        }
    }
}
