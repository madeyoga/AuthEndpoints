using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.ReAuth;

/// <summary>
/// Step-up with a fresh sign-in at a linked external provider.
/// Start (signed in) returns a launch URL. Launch starts the provider challenge with one-time state.
/// The callback checks the state and that the provider login belongs to the same user, then issues the
/// ReAuth cookie (cookie sessions) or a one-time code that bearer clients exchange at complete.
/// It never signs anyone in and never links a login.
/// </summary>
internal static class ExternalReAuthEndpoints<TUser>
    where TUser : class, new()
{
    internal const string StateItem = "AuthEndpoints.ExternalReAuth";
    internal const string CodeQuery = "reauthCode";
    internal const string LaunchEndpointName = "ExternalReAuthLaunch";
    internal const string CallbackEndpointName = "ExternalReAuthCallback";
    internal static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(2);
    internal static readonly TimeSpan AuthTimeSkew = TimeSpan.FromMinutes(1);

    public static async Task<IResult> Start(
        string provider,
        ExternalReAuthStartRequest? request,
        HttpContext context,
        UserManager<TUser> userManager,
        LinkGenerator linkGenerator)
    {
        var services = context.RequestServices;
        var reAuth = services.GetRequiredService<IOptions<AuthEndpointsReAuthOptions>>().Value;
        var externalOptions = services.GetRequiredService<IOptions<ExternalAuthOptions>>().Value;
        var logger = Logger(services);
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var userId = await userManager.GetUserIdAsync(user);
        if (!IsAvailable(services, reAuth, provider))
        {
            ExternalReAuthLog.Rejected(logger, userId, provider, "unavailable");
            return Results.NotFound();
        }

        if (!await HasLoginAsync(userManager, user, provider))
        {
            ExternalReAuthLog.Rejected(logger, userId, provider, "login_not_linked");
            return Results.Problem(
                title: "login_not_linked",
                detail: "The account has no linked login for this provider.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var returnUrl = ExternalAuthReturnUrl.Resolve(
            request?.ReturnUrl,
            externalOptions.DefaultReturnUrl,
            externalOptions.AllowedReturnUrlOrigins.ToList());

        var state = new ExternalReAuthState(
            userId,
            provider,
            NewNonce(),
            Now(services).ToUnixTimeSeconds(),
            returnUrl,
            await ReAuthEndpoints<TUser>.ShouldIssueReAuthCookieAsync(context),
            await StampAsync(userManager, user));

        var ticket = Protector(services, StatePurpose).Protect(state);
        var launch = linkGenerator.GetUriByName(context, LaunchEndpointName, new { provider, ticket });
        if (string.IsNullOrEmpty(launch))
        {
            return Results.Problem(
                detail: "External step-up launch endpoint was not found.",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        ExternalReAuthLog.Started(logger, userId, provider);
        return Results.Ok(new ExternalReAuthStartResponse { RedirectUrl = launch });
    }

    public static async Task<IResult> Launch(
        string provider,
        string? ticket,
        HttpContext context,
        LinkGenerator linkGenerator,
        IAuthenticationSchemeProvider schemes)
    {
        var services = context.RequestServices;
        var reAuth = services.GetRequiredService<IOptions<AuthEndpointsReAuthOptions>>().Value;
        var externalOptions = services.GetRequiredService<IOptions<ExternalAuthOptions>>().Value;
        if (!IsAvailable(services, reAuth, provider))
        {
            return Results.NotFound();
        }

        var state = string.IsNullOrEmpty(ticket) ? null : Protector(services, StatePurpose).Unprotect<ExternalReAuthState>(ticket);
        if (state is null
            || !string.Equals(state.Provider, provider, StringComparison.Ordinal)
            || IsExpired(services, state.CreatedUnix, reAuth.External.RequestLifetime))
        {
            return Fail(context, externalOptions, Logger(services), state?.UserId, provider, "invalid_request",
                "The step-up request is invalid or expired.");
        }

        var callback = linkGenerator.GetPathByName(context, CallbackEndpointName, new { provider });
        if (string.IsNullOrEmpty(callback))
        {
            return Results.Problem(
                detail: "External step-up callback endpoint was not found.",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        var properties = new AuthenticationProperties { RedirectUri = callback };
        properties.Items["LoginProvider"] = provider;
        properties.Items[StateItem] = ticket;
        await ConfigureFreshSignInAsync(services, schemes, provider, properties);
        return Results.Challenge(properties, [provider]);
    }

    public static async Task<IResult> Callback(
        string provider,
        string? error,
        string? error_description,
        HttpContext context,
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager)
    {
        var services = context.RequestServices;
        var reAuth = services.GetRequiredService<IOptions<AuthEndpointsReAuthOptions>>().Value;
        var externalOptions = services.GetRequiredService<IOptions<ExternalAuthOptions>>().Value;
        var logger = Logger(services);

        try
        {
            if (!IsAvailable(services, reAuth, provider))
            {
                return Results.NotFound();
            }

            if (!string.IsNullOrEmpty(error))
            {
                return Fail(context, externalOptions, logger, null, provider, error,
                    error_description ?? "The external provider returned an error.");
            }

            var info = await signInManager.GetExternalLoginInfoAsync();
            if (info is null
                || info.AuthenticationProperties?.Items.TryGetValue(StateItem, out var ticket) != true
                || string.IsNullOrEmpty(ticket))
            {
                return Fail(context, externalOptions, logger, null, provider, "invalid_request",
                    "The step-up request is invalid or expired.");
            }

            var state = Protector(services, StatePurpose).Unprotect<ExternalReAuthState>(ticket);
            if (state is null
                || !string.Equals(state.Provider, provider, StringComparison.Ordinal)
                || !string.Equals(info.LoginProvider, provider, StringComparison.Ordinal)
                || IsExpired(services, state.CreatedUnix, reAuth.External.RequestLifetime))
            {
                return Fail(context, externalOptions, logger, state?.UserId, provider, "invalid_request",
                    "The step-up request is invalid or expired.");
            }

            var ledger = services.GetRequiredService<ExternalReAuthReplayLedger>();
            var stateExpires = DateTimeOffset.FromUnixTimeSeconds(state.CreatedUnix).Add(reAuth.External.RequestLifetime);
            if (!ledger.TryConsume("state:" + state.Nonce, stateExpires))
            {
                return Fail(context, externalOptions, logger, state.UserId, provider, "invalid_request",
                    "The step-up request was already used.");
            }

            var user = await userManager.FindByIdAsync(state.UserId);
            if (user is null || !string.Equals(await StampAsync(userManager, user), state.Stamp, StringComparison.Ordinal))
            {
                return Fail(context, externalOptions, logger, state.UserId, provider, "invalid_request",
                    "The step-up request is no longer valid.");
            }

            var owner = await userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            if (owner is null)
            {
                return Fail(context, externalOptions, logger, state.UserId, provider, "login_not_linked",
                    "This provider account is not linked to your account.");
            }

            if (!string.Equals(await userManager.GetUserIdAsync(owner), state.UserId, StringComparison.Ordinal))
            {
                return Fail(context, externalOptions, logger, state.UserId, provider, "user_mismatch",
                    "This provider account belongs to a different user.");
            }

            if (IsStaleAuthTime(info.Principal, state.CreatedUnix))
            {
                return Fail(context, externalOptions, logger, state.UserId, provider, "stale_sign_in",
                    "The provider did not report a fresh sign-in.");
            }

            var now = Now(services);
            string redirect;
            if (state.Cookie)
            {
                var session = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
                var sessionUserId = session.Succeeded ? userManager.GetUserId(session.Principal!) : null;
                if (!string.Equals(sessionUserId, state.UserId, StringComparison.Ordinal))
                {
                    return Fail(context, externalOptions, logger, state.UserId, provider, "user_mismatch",
                        "The signed-in user changed during step-up.");
                }

                var claims = await ReAuthEndpoints<TUser>.CreateProofClaimsAsync(session.Principal!, userManager, user, now);
                var scheme = AuthEndpointsConstants.ReAuthScheme;
                await context.SignInAsync(
                    scheme,
                    new ClaimsPrincipal(new ClaimsIdentity(claims, scheme)),
                    new AuthenticationProperties { IsPersistent = false, ExpiresUtc = now.Add(reAuth.Lifetime) });
                redirect = state.ReturnUrl;
            }
            else
            {
                var code = Protector(services, CodePurpose).Protect(
                    new ExternalReAuthCode(state.UserId, NewNonce(), now.ToUnixTimeSeconds(), state.Stamp));
                redirect = QueryHelpers.AddQueryString(state.ReturnUrl, CodeQuery, code);
            }

            ExternalReAuthLog.Succeeded(logger, state.UserId, provider, state.Cookie ? "cookie" : "bearer");
            return Results.Redirect(redirect);
        }
        finally
        {
            await context.SignOutAsync(IdentityConstants.ExternalScheme);
        }
    }

    public static async Task<IResult> Complete(
        ExternalReAuthCompleteRequest? request,
        HttpContext context,
        UserManager<TUser> userManager)
    {
        var services = context.RequestServices;
        var logger = Logger(services);
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var userId = await userManager.GetUserIdAsync(user);
        var code = string.IsNullOrEmpty(request?.Code) ? null : Protector(services, CodePurpose).Unprotect<ExternalReAuthCode>(request.Code);
        if (code is null
            || IsExpired(services, code.CreatedUnix, CodeLifetime)
            || !string.Equals(code.UserId, userId, StringComparison.Ordinal)
            || !string.Equals(code.Stamp, await StampAsync(userManager, user), StringComparison.Ordinal)
            || !services.GetRequiredService<ExternalReAuthReplayLedger>().TryConsume(
                "code:" + code.Nonce,
                DateTimeOffset.FromUnixTimeSeconds(code.CreatedUnix).Add(CodeLifetime)))
        {
            ExternalReAuthLog.Rejected(logger, userId, null, "invalid_code");
            return Results.Unauthorized();
        }

        var claims = await ReAuthEndpoints<TUser>.CreateProofClaimsAsync(context.User, userManager, user, Now(services));
        var token = services.GetRequiredService<ReAuthTokenService>().CreateToken(claims);
        ExternalReAuthLog.Completed(logger, userId);
        return Results.Ok(new ConfirmIdentityResponse { ReauthToken = token });
    }

    internal static async Task<IReadOnlyList<ExternalAuthMethod>> ListMethodsAsync(
        IServiceProvider services,
        UserManager<TUser> userManager,
        TUser user)
    {
        if (!AuthEndpointsModules.IsRegistered<ExternalAuthEndpointsModule>(services)
            || services.GetService<ExternalReAuthMapMarker>() is not { Mapped: true })
        {
            return [];
        }

        var reAuth = services.GetRequiredService<IOptions<AuthEndpointsReAuthOptions>>().Value;
        if (!reAuth.External.Enabled)
        {
            return [];
        }

        var providers = services.GetServices<IExternalAuthProvider>().Select(p => p.Scheme).ToHashSet(StringComparer.Ordinal);
        var schemes = services.GetRequiredService<IAuthenticationSchemeProvider>();
        var methods = new List<ExternalAuthMethod>();
        foreach (var login in await userManager.GetLoginsAsync(user))
        {
            var scheme = login.LoginProvider;
            if (!providers.Contains(scheme)
                || !reAuth.External.IsAllowed(scheme)
                || methods.Any(m => string.Equals(m.Scheme, scheme, StringComparison.Ordinal)))
            {
                continue;
            }

            var registered = await schemes.GetSchemeAsync(scheme);
            if (registered is null)
            {
                continue;
            }

            methods.Add(new ExternalAuthMethod(scheme, registered.DisplayName ?? login.ProviderDisplayName ?? scheme));
        }

        return methods;
    }

    internal static bool IsStaleAuthTime(ClaimsPrincipal principal, long startedUnix)
    {
        var value = principal.FindFirst("auth_time")?.Value;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var authTime))
        {
            return true;
        }

        return authTime < startedUnix - (long)AuthTimeSkew.TotalSeconds;
    }

    private const string StatePurpose = "AuthEndpoints.ExternalReAuth.State.v1";
    private const string CodePurpose = "AuthEndpoints.ExternalReAuth.Code.v1";

    private static bool IsAvailable(IServiceProvider services, AuthEndpointsReAuthOptions reAuth, string provider) =>
        reAuth.External.IsAllowed(provider)
        && services.GetServices<IExternalAuthProvider>().Any(p => string.Equals(p.Scheme, provider, StringComparison.Ordinal));

    private static async Task<bool> HasLoginAsync(UserManager<TUser> userManager, TUser user, string provider) =>
        (await userManager.GetLoginsAsync(user)).Any(l => string.Equals(l.LoginProvider, provider, StringComparison.Ordinal));

    private static async Task<string?> StampAsync(UserManager<TUser> userManager, TUser user) =>
        userManager.SupportsUserSecurityStamp ? await userManager.GetSecurityStampAsync(user) : null;

    private static async Task ConfigureFreshSignInAsync(
        IServiceProvider services,
        IAuthenticationSchemeProvider schemes,
        string provider,
        AuthenticationProperties properties)
    {
        var registered = services.GetServices<IExternalAuthProvider>()
            .FirstOrDefault(p => string.Equals(p.Scheme, provider, StringComparison.Ordinal));
        if (registered is IExternalReAuthChallenge custom)
        {
            custom.ConfigureFreshSignIn(properties);
            return;
        }

        var scheme = await schemes.GetSchemeAsync(provider);
        if (scheme is not null && IsOpenIdConnect(scheme.HandlerType))
        {
            properties.Parameters["prompt"] = "login";
            properties.Parameters["max_age"] = TimeSpan.Zero;
        }
    }

    private static bool IsOpenIdConnect(Type? type)
    {
        for (; type is not null; type = type.BaseType)
        {
            if (string.Equals(type.FullName, "Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectHandler", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsExpired(IServiceProvider services, long createdUnix, TimeSpan lifetime) =>
        Now(services) >= DateTimeOffset.FromUnixTimeSeconds(createdUnix).Add(lifetime);

    private static DateTimeOffset Now(IServiceProvider services) =>
        services.GetRequiredService<TimeProvider>().GetUtcNow();

    private static string NewNonce() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));

    private static IDataProtector Protector(IServiceProvider services, string purpose) =>
        services.GetRequiredService<IDataProtectionProvider>().CreateProtector(purpose);

    private static ILogger Logger(IServiceProvider services) =>
        services.GetRequiredService<ILoggerFactory>().CreateLogger(ExternalReAuthLog.Category);

    private static IResult Fail(
        HttpContext context,
        ExternalAuthOptions options,
        ILogger logger,
        string? userId,
        string provider,
        string error,
        string description)
    {
        ExternalReAuthLog.Rejected(logger, userId, provider, error);
        return ExternalAuthErrorResults.Create(context, options, error, description, StatusCodes.Status400BadRequest);
    }
}

internal sealed record ExternalReAuthState(
    string UserId,
    string Provider,
    string Nonce,
    long CreatedUnix,
    string ReturnUrl,
    bool Cookie,
    string? Stamp);

internal sealed record ExternalReAuthCode(string UserId, string Nonce, long CreatedUnix, string? Stamp);

/// <summary>Set when the external step-up routes are mapped, so the methods list only offers what can be used.</summary>
internal sealed class ExternalReAuthMapMarker
{
    public bool Mapped { get; set; }
}

/// <summary>
/// Remembers used step-up nonces until they expire so state and codes work once.
/// In-process: hosts running several instances should route a step-up to one instance or accept
/// that a reused nonce on another instance is still bound to the same user and provider login.
/// </summary>
internal sealed class ExternalReAuthReplayLedger(TimeProvider timeProvider)
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _used = new(StringComparer.Ordinal);

    public bool TryConsume(string nonce, DateTimeOffset expires)
    {
        var now = timeProvider.GetUtcNow();
        foreach (var entry in _used)
        {
            if (entry.Value <= now)
            {
                _used.TryRemove(entry);
            }
        }

        return _used.TryAdd(nonce, expires);
    }
}

internal static class ExternalReAuthProtectorExtensions
{
    public static string Protect<T>(this IDataProtector protector, T payload) =>
        WebEncoders.Base64UrlEncode(protector.Protect(JsonSerializer.SerializeToUtf8Bytes(payload)));

    public static T? Unprotect<T>(this IDataProtector protector, string value)
        where T : class
    {
        try
        {
            return JsonSerializer.Deserialize<T>(protector.Unprotect(WebEncoders.Base64UrlDecode(value)));
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException)
        {
            return null;
        }
    }
}

internal static partial class ExternalReAuthLog
{
    public const string Category = "AuthEndpoints.ExternalReAuth";

    [LoggerMessage(EventId = 1, EventName = "ExternalReAuthStarted", Level = LogLevel.Information,
        Message = "External step-up started for user {UserId} with provider {Provider}.")]
    public static partial void Started(ILogger logger, string? userId, string provider);

    [LoggerMessage(EventId = 2, EventName = "ExternalReAuthSucceeded", Level = LogLevel.Information,
        Message = "External step-up succeeded for user {UserId} with provider {Provider} ({Mode}).")]
    public static partial void Succeeded(ILogger logger, string? userId, string provider, string mode);

    [LoggerMessage(EventId = 3, EventName = "ExternalReAuthRejected", Level = LogLevel.Warning,
        Message = "External step-up rejected for user {UserId} with provider {Provider}: {Reason}.")]
    public static partial void Rejected(ILogger logger, string? userId, string? provider, string reason);

    [LoggerMessage(EventId = 4, EventName = "ExternalReAuthCompleted", Level = LogLevel.Information,
        Message = "External step-up code exchanged for user {UserId}.")]
    public static partial void Completed(ILogger logger, string? userId);
}
