using System.Security.Claims;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
var dbPath = Path.Combine(Path.GetTempPath(), $"ae-oauth-{Guid.NewGuid():N}.sqlite");
var autoLink = string.Equals(builder.Configuration["AE_AUTOLINK"], "true", StringComparison.OrdinalIgnoreCase);

builder.Services.AddDbContext<OAuthDb>(options => options.UseSqlite($"Data Source={dbPath}"));
builder.Services
    .AddIdentity<OAuthUser, IdentityRole>(options =>
    {
        options.Password.RequiredLength = 6;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireLowercase = false;
        options.Password.RequireDigit = false;
        options.SignIn.RequireConfirmedAccount = false;
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
    options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    };
});

builder.Services.AddSingleton<CapturedChallenge>();
builder.Services.AddAuthentication()
    .AddScheme<AuthenticationSchemeOptions, CapturingAuthHandler>("Fake", _ => { });

builder.Services.AddExternalAuthEndpoints<OAuthUser>(options =>
{
    options.AutoLinkByEmail = autoLink;
    options.DefaultReturnUrl = "/";
    options.ErrorPath = "/auth/external/error";
    options.AllowedReturnUrlOrigins.Add("https://app.example.com");
}).AddProvider(new FakeExternalAuthProvider());

builder.Services.AddReAuthScheme();
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<OAuthDb>();
    await db.Database.EnsureCreatedAsync();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

var external = app.MapGroup("/auth/external");
external.MapExternalAuthProvider<OAuthUser>("Fake");
external.MapExternalAccountEndpoints<OAuthUser>();

app.MapPost("/test/user", async (CreateUser body, UserManager<OAuthUser> users) =>
{
    var user = new OAuthUser { UserName = body.Email, Email = body.Email, EmailConfirmed = body.EmailConfirmed };
    var result = string.IsNullOrEmpty(body.Password)
        ? await users.CreateAsync(user)
        : await users.CreateAsync(user, body.Password);
    return result.Succeeded ? Results.Ok(new { id = user.Id }) : Results.BadRequest(result.Errors);
});

app.MapPost("/test/signin", async (string email, SignInManager<OAuthUser> signIn, UserManager<OAuthUser> users) =>
{
    var user = await users.FindByEmailAsync(email);
    if (user is null)
    {
        return Results.NotFound();
    }

    await signIn.SignInAsync(user, isPersistent: false);
    return Results.NoContent();
});

app.MapPost("/test/reauth", async (HttpContext http) =>
{
    if (http.User.Identity?.IsAuthenticated != true)
    {
        return Results.Unauthorized();
    }

    var claims = http.User.Claims.Append(new Claim("Reauth", "true"));
    var identity = new ClaimsIdentity(claims, AuthEndpointsConstants.ReAuthScheme);
    await http.SignInAsync(AuthEndpointsConstants.ReAuthScheme, new ClaimsPrincipal(identity));
    return Results.NoContent();
});

app.MapGet("/test/csrf", (HttpContext http, IAntiforgery antiforgery) =>
{
    var tokens = antiforgery.GetAndStoreTokens(http);
    return Results.Ok(new { token = tokens.RequestToken });
});

app.MapPost("/test/external-cookie", async (ExternalCookie body, HttpContext http) =>
{
    var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, body.Key) };
    if (!string.IsNullOrEmpty(body.Email))
    {
        claims.Add(new Claim(ClaimTypes.Email, body.Email));
    }

    if (body.Verified)
    {
        claims.Add(new Claim(ExternalEmailClaims.EmailVerifiedClaimType, "true"));
    }

    var identity = new ClaimsIdentity(claims, IdentityConstants.ExternalScheme);
    var properties = new AuthenticationProperties();
    properties.Items["LoginProvider"] = body.Provider;
    if (!string.IsNullOrEmpty(body.Xsrf))
    {
        properties.Items["XsrfId"] = body.Xsrf;
    }

    await http.SignInAsync(IdentityConstants.ExternalScheme, new ClaimsPrincipal(identity), properties);
    return Results.NoContent();
});

app.MapGet("/test/external-info", async (SignInManager<OAuthUser> signIn) =>
{
    var info = await signIn.GetExternalLoginInfoAsync();
    return info is null
        ? Results.NotFound()
        : Results.Ok(new { info.LoginProvider, info.ProviderKey });
});

app.MapGet("/test/challenge", (CapturedChallenge captured) =>
    Results.Ok(new { xsrf = captured.Properties?.Items.TryGetValue("XsrfId", out var id) == true ? id : null }));

app.Run();

internal sealed class OAuthDb : IdentityDbContext<OAuthUser>
{
    public OAuthDb(DbContextOptions<OAuthDb> options) : base(options) { }
}

internal sealed class OAuthUser : IdentityUser;

internal sealed record CreateUser(string Email, string? Password, bool EmailConfirmed);

internal sealed record ExternalCookie(string Provider, string Key, string? Email, bool Verified, string? Xsrf);

internal sealed class FakeExternalAuthProvider : IExternalAuthProvider
{
    public string Scheme => "Fake";
    public string LoginPath => "login/fake";
    public string CallbackPath => "login/fake/callback";
    public string CallbackEndpointName => "FakeLoginCallback";
}

internal sealed class CapturedChallenge
{
    public AuthenticationProperties? Properties { get; set; }
}

internal sealed class CapturingAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public CapturingAuthHandler(
        Microsoft.Extensions.Options.IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
        Task.FromResult(AuthenticateResult.NoResult());

    protected override Task HandleChallengeAsync(AuthenticationProperties? properties)
    {
        Context.RequestServices.GetRequiredService<CapturedChallenge>().Properties = properties;
        Response.Redirect(properties?.RedirectUri ?? "/");
        return Task.CompletedTask;
    }
}

public partial class Program;
