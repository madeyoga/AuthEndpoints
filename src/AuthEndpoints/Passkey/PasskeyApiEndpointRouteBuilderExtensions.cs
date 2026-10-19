using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Passkey;

public static class PasskeyApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps passkey register, login, and credential management endpoints under <c>/passkeys</c>.
    /// This is <see cref="MapPasskeySignInEndpoints{TUser}"/> without auto-mapping confirm-email,
    /// plus <see cref="MapPasskeyManagementEndpoints{TUser}"/>, on one <c>/passkeys</c> group.
    /// The sign-in completer stays Identity bearer. Antiforgery stays on, because this map is the
    /// 3.x surface used beside cookie sign-in. Pass <see cref="AuthEndpointsSession.IdentityBearer"/>
    /// to omit it. <see cref="MapBearerAuthEndpoints{TUser}"/> maps no <c>csrfToken</c> route, and
    /// the bearer facade passes that session. JWT body refresh omits it when the session is
    /// <see cref="AuthEndpointsSession.Jwt"/>.
    /// </summary>
    /// <param name="confirmEmailEndpointName">
    /// Optional unique endpoint name for confirm-email link generation after passwordless register.
    /// Defaults to <see cref="AuthEndpointsEndpointNames.ConfirmEmail{TUser}"/>. Required when that map
    /// used a custom name. This method does not map the confirm-email route.
    /// </param>
    /// <exception cref="NotSupportedException">
    /// The user store does not support passkeys or email. This module is email-keyed and requires
    /// a passkey store.
    /// </exception>
    public static IEndpointConventionBuilder MapPasskeyEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        return MapPasskeyEndpoints<TUser>(endpoints, AuthEndpointsSession.Cookie, confirmEmailEndpointName);
    }

    /// <summary>
    /// Maps passkey register, login, and credential management for <paramref name="session"/>.
    /// Antiforgery is required for <see cref="AuthEndpointsSession.Cookie"/> and for
    /// <see cref="AuthEndpointsSession.Jwt"/> with cookie refresh transport. Identity bearer and
    /// JWT with body refresh transport omit it. The 3.x completer is unchanged: register and login
    /// still use Identity bearer unless the host registered another passkey completer.
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeyEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        AuthEndpointsSession session,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        EnsurePasskeyAndEmailSupport<TUser>(endpoints.ServiceProvider);
        WarnIfPasskeysMissing(endpoints, nameof(MapPasskeyEndpoints));

        confirmEmailEndpointName ??= AuthEndpointsEndpointNames.ConfirmEmail<TUser>();
        var group = endpoints.MapGroup("/passkeys");
        MapPasskeyRoutes<TUser>(
            group,
            confirmEmailEndpointName,
            nameof(MapPasskeyEndpoints),
            signIn: true,
            management: true,
            completer: null,
            honorDefault: false,
            session);
        return group;
    }

    /// <summary>
    /// Maps passkey sign-up and sign-in under <c>/passkeys</c>
    /// (<c>requestOptions</c>, <c>login</c>, <c>register/options</c>, <c>register</c>).
    /// Maps confirm-email on the parent builder when that endpoint name is not mapped yet.
    /// The returned builder includes that confirm-email group, so later conventions apply to confirm and resend.
    /// When the name is already mapped, <see cref="ConfirmEmailEndpointRouteBuilderExtensions.MapConfirmEmailEndpoints{TUser}"/>
    /// contributes a no-op builder and those conventions do not reach the existing route.
    /// Register and login keep the 3.x completer: an explicitly registered
    /// <see cref="IPasskeySignInCompleter{TUser}"/>, otherwise Identity bearer.
    /// A single string is the confirm-email endpoint name, not a completer.
    /// When that string matches a registered completer name, this method logs a warning and still
    /// treats it as the confirm-email name. Pass <see cref="AuthEndpointsSession"/> to select a session.
    /// Antiforgery follows that session. The Identity bearer default omits it.
    /// A cookie session and JWT with cookie refresh transport require it.
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeySignInEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        WarnIfConfirmNameMatchesCompleter(endpoints, confirmEmailEndpointName);
        return MapPasskeySignInCore<TUser>(endpoints, confirmEmailEndpointName, completer: null);
    }

    /// <summary>
    /// Maps passkey sign-in and finishes register and login with the built-in completer for <paramref name="session"/>.
    /// Antiforgery is required for <see cref="AuthEndpointsSession.Cookie"/> and for
    /// <see cref="AuthEndpointsSession.Jwt"/> with cookie refresh transport. Identity bearer and
    /// JWT with body refresh transport omit it. Identity bearer maps no <c>csrfToken</c> route.
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeySignInEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        AuthEndpointsSession session,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return MapPasskeySignInCore<TUser>(endpoints, confirmEmailEndpointName, SignInCompleterMap.FromSession(session));
    }

    /// <summary>
    /// Maps passkey sign-in and finishes register and login with the keyed completer <paramref name="completer"/>.
    /// <paramref name="confirmEmailEndpointName"/> is required so a single string still selects the 3.x confirm-email name.
    /// Pass <see langword="null"/> to use <see cref="AuthEndpointsEndpointNames.ConfirmEmail{TUser}"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeySignInEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string completer,
        string? confirmEmailEndpointName)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(completer);
        return MapPasskeySignInCore<TUser>(endpoints, confirmEmailEndpointName, completer);
    }

    private static IEndpointConventionBuilder MapPasskeySignInCore<TUser>(
        IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName,
        string? completer)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        EnsurePasskeyAndEmailSupport<TUser>(endpoints.ServiceProvider);
        WarnIfNeitherPasskeyModule<PasskeySignInEndpointsModule>(
            endpoints,
            "AddPasskeySignInEndpoints",
            nameof(MapPasskeySignInEndpoints));
        if (completer is null)
        {
            SignInCompleterMap.EnsureConfiguredDefault<TUser>(
                endpoints,
                nameof(MapPasskeySignInEndpoints),
                LegacySignInCompleters.PasskeyWins<TUser>(endpoints.ServiceProvider));
        }
        else
        {
            SignInCompleterMap.EnsureSelected<TUser>(endpoints, completer, nameof(MapPasskeySignInEndpoints));
        }

        confirmEmailEndpointName ??= AuthEndpointsEndpointNames.ConfirmEmail<TUser>();
        var group = endpoints.MapGroup("/passkeys");
        MapPasskeyRoutes<TUser>(
            group,
            confirmEmailEndpointName,
            nameof(MapPasskeySignInEndpoints),
            signIn: true,
            management: false,
            completer,
            honorDefault: completer is null,
            SessionFor<TUser>(endpoints, completer, honorDefault: completer is null));
        var confirm = endpoints.MapConfirmEmailEndpoints<TUser>(confirmEmailEndpointName);
        return new CompositeEndpointConventionBuilder(group, confirm);
    }

    /// <summary>
    /// Maps signed-in passkey credential management under <c>/passkeys</c>
    /// (<c>creationOptions</c>, <c>POST /</c>, <c>GET /</c>, <c>PATCH /</c>, <c>DELETE /{credentialIdUrl}</c>).
    /// Antiforgery is required. Cookie sessions and the shared management route use this overload.
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeyManagementEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        return MapPasskeyManagementEndpoints<TUser>(endpoints, AuthEndpointsSession.Cookie);
    }

    /// <summary>
    /// Maps signed-in passkey credential management for <paramref name="session"/>.
    /// Antiforgery is required for <see cref="AuthEndpointsSession.Cookie"/> and for
    /// <see cref="AuthEndpointsSession.Jwt"/> with cookie refresh transport. Identity bearer and
    /// JWT with body refresh transport omit it.
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeyManagementEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        AuthEndpointsSession session)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        EnsurePasskeyAndEmailSupport<TUser>(endpoints.ServiceProvider);
        WarnIfNeitherPasskeyModule<PasskeyManagementEndpointsModule>(
            endpoints,
            "AddPasskeyManagementEndpoints",
            nameof(MapPasskeyManagementEndpoints));

        var group = endpoints.MapGroup("/passkeys");
        MapPasskeyRoutes<TUser>(
            group,
            confirmEmailEndpointName: null,
            nameof(MapPasskeyManagementEndpoints),
            signIn: false,
            management: true,
            completer: null,
            honorDefault: false,
            session);
        return group;
    }

    private static void WarnIfConfirmNameMatchesCompleter(IEndpointRouteBuilder endpoints, string? confirmEmailEndpointName)
    {
        if (string.IsNullOrWhiteSpace(confirmEmailEndpointName)
            || !SignInCompleterRegistry.MatchesAny(endpoints.ServiceProvider, confirmEmailEndpointName))
        {
            return;
        }

        AuthEndpointsModules.Log(
            endpoints,
            $"MapPasskeySignInEndpoints treated '{confirmEmailEndpointName}' as the confirm-email endpoint name, not a sign-in completer. Pass AuthEndpointsSession, or pass completer: \"{confirmEmailEndpointName}\" together with confirmEmailEndpointName.");
    }

    private static void WarnIfPasskeysMissing(IEndpointRouteBuilder endpoints, string mapMethod)
    {
        AuthEndpointsModules.ThrowIfMissing<PasskeyEndpointsModule>(endpoints, "AddPasskeyEndpoints", mapMethod);
    }

    private static void MapPasskeyRoutes<TUser>(
        IEndpointRouteBuilder group,
        string? confirmEmailEndpointName,
        string mapMethod,
        bool signIn,
        bool management,
        string? completer,
        bool honorDefault,
        AuthEndpointsSession session)
        where TUser : class, new()
    {
        // creationOptions is mapped before the anonymous ceremonies, and credential
        // changes after them, so MapPasskeyEndpoints keeps the 3.3.0 OpenAPI order.
        RouteGroupBuilder? secured = null;
        if (management)
        {
            secured = group.MapGroup(string.Empty)
                .RequireAuthEndpointsUser();

            secured.MapPost("/creationOptions", PasskeyEndpoints<TUser>.CreationOptions)
                .WithSummary("Generate WebAuthn creation options for the signed-in user.")
                .RequireReauth()
                .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
                .RequirePasskeyCeremonyAntiforgery(group, session)
                .Track(group, mapMethod);
        }

        if (signIn)
        {
            MapPasskeySignInRoutes<TUser>(group, confirmEmailEndpointName!, mapMethod, completer, honorDefault, session);
        }

        if (!management || secured is null)
        {
            return;
        }

        secured.MapPost("/", PasskeyEndpoints<TUser>.AddPasskey)
            .WithSummary("Attest and store a passkey on the signed-in account.")
            .RequireReauth()
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyRegisterPolicy)
            .RequirePasskeyCeremonyAntiforgery(group, session)
            .Track(group, mapMethod);

        secured.MapGet("/", PasskeyEndpoints<TUser>.ListPasskeys)
            .WithSummary("List passkeys for the signed-in user.")
            .Track(group, mapMethod);

        secured.MapPatch("/", PasskeyEndpoints<TUser>.RenamePasskey)
            .WithSummary("Rename a passkey.")
            .WithDescription("Trims the name. A name longer than 200 characters is rejected.")
            .RequireReauth()
            .RequirePasskeyCeremonyAntiforgery(group, session)
            .Track(group, mapMethod);

        secured.MapDelete("/{credentialIdUrl}", PasskeyEndpoints<TUser>.DeletePasskey)
            .WithSummary("Remove a passkey from the signed-in account.")
            .WithDescription("""
                Refuses with a validation problem when this passkey is the user's only sign-in method
                (no password and no external login).
                """)
            .RequireReauth()
            .RequirePasskeyCeremonyAntiforgery(group, session)
            .Track(group, mapMethod);
    }

    private static void MapPasskeySignInRoutes<TUser>(
        IEndpointRouteBuilder group,
        string confirmEmailEndpointName,
        string mapMethod,
        string? completer,
        bool honorDefault,
        AuthEndpointsSession session,
        bool requestOptions = true,
        bool registerOptions = true,
        bool register = true,
        bool loginRoute = true)
        where TUser : class, new()
    {
        if (requestOptions)
        {
            group.MapPost("/requestOptions", PasskeyEndpoints<TUser>.RequestOptions)
                .WithSummary("Generate WebAuthn request options for passkey login.")
                .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
                .RequirePasskeyCeremonyAntiforgery(group, session)
                .Track(group, mapMethod);
        }

        if (registerOptions)
        {
            group.MapPost("/register/options", PasskeyEndpoints<TUser>.RegisterOptions)
                .WithSummary("Generate WebAuthn creation options for passwordless account registration.")
                .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
                .RequirePasskeyCeremonyAntiforgery(group, session)
                .Track(group, mapMethod);
        }

        RouteHandlerBuilder? registerEndpoint = null;
        if (register)
        {
            registerEndpoint = group.MapPost("/register", (
                [FromBody] PasskeyRegisterRequest request,
                [FromQuery] bool? useCookies,
                [FromQuery] bool? useSessionCookies,
                HttpContext httpContext,
                UserManager<TUser> userManager,
                IUserStore<TUser> userStore,
                SignInManager<TUser> signInManager,
                IPasskeySignInCompleter<TUser> legacyCompleter,
                CancellationToken cancellationToken) => PasskeyEndpoints<TUser>.Register(
                    request,
                    useCookies,
                    useSessionCookies,
                    httpContext,
                    userManager,
                    userStore,
                    signInManager,
                    legacyCompleter,
                    confirmEmailEndpointName,
                    cancellationToken))
                .WithSummary("Create a passwordless account and store the attested passkey.")
                .WithDescription("""
                    After a successful user create, sends the same confirmation email as password register.
                    Sign-in is completed by IPasskeySignInCompleter unless the map selected a session or completer.
                    Default IdentityPasskeySignInCompleter: useCookies / useSessionCookies select the application cookie
                    and the body is credentialId; otherwise Identity bearer tokens are issued and that token body is the response.
                    Pass session: AuthEndpointsSession.Jwt or completer: SignInCompleters.Jwt for Simple JWT
                    (access token + refresh cookie, no credentialId).
                    When sign-in is not allowed, the body is credentialId and no session is issued.
                    CSRF (antiforgery) is required for a cookie session and for JWT with cookie refresh transport.
                    Identity bearer and JWT with body refresh transport do not require it.
                    """)
                .RequireRateLimiting(AuthEndpointsConstants.PasskeyRegisterPolicy)
                .RequirePasskeyCeremonyAntiforgery(group, session)
                .Track(group, mapMethod);
        }

        RouteHandlerBuilder? login = null;
        if (loginRoute)
        {
            login = group.MapPost("/login", PasskeyEndpoints<TUser>.Login)
                .WithSummary("Sign in with a passkey assertion.")
                .WithDescription("""
                    Completes sign-in via IPasskeySignInCompleter unless the map selected a session or completer.
                    Default IdentityPasskeySignInCompleter:
                    ?useCookies=true → persistent application cookie;
                    ?useSessionCookies=true → session application cookie;
                    neither → Identity bearer token (AccessTokenResponse).
                    Pass session: AuthEndpointsSession.Jwt or completer: SignInCompleters.Jwt for Simple JWT
                    (access token + refresh cookie).
                    CSRF (antiforgery) is required for a cookie session and for JWT with cookie refresh transport.
                    Identity bearer and JWT with body refresh transport do not require it.
                    """)
                .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
                .RequirePasskeyCeremonyAntiforgery(group, session)
                .Track(group, mapMethod);
        }

        if (completer is not null)
        {
            var selection = new SignInCompleterSelection(completer);
            registerEndpoint?.WithMetadata(selection);
            login?.WithMetadata(selection);
        }
        else if (honorDefault)
        {
            var honor = new HonorSignInCompletionDefault();
            registerEndpoint?.WithMetadata(honor);
            login?.WithMetadata(honor);
        }
    }

    /// <summary>
    /// Maps <c>POST /passkeys/register</c>. Register signs the user in when confirmation is off
    /// and only creates the account when it is on, so this route is mapped per session.
    /// A single string is the confirm-email endpoint name, not a completer.
    /// Also maps confirm-email on the parent builder when that name is not mapped yet.
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeySignUpEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        WarnIfConfirmNameMatchesCompleter(endpoints, confirmEmailEndpointName);
        return MapPasskeyRegisterCore<TUser>(
            endpoints,
            confirmEmailEndpointName,
            completer: null,
            ensureConfirmEmail: true,
            honorDefault: true,
            nameof(MapPasskeySignUpEndpoints),
            warn: true);
    }

    /// <summary>
    /// Maps <c>POST /passkeys/register</c> and finishes it with the built-in completer for <paramref name="session"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeySignUpEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        AuthEndpointsSession session,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return MapPasskeyRegisterCore<TUser>(
            endpoints,
            confirmEmailEndpointName,
            SignInCompleterMap.FromSession(session),
            ensureConfirmEmail: true,
            honorDefault: false,
            nameof(MapPasskeySignUpEndpoints),
            warn: true);
    }

    /// <summary>
    /// Maps <c>POST /passkeys/register</c> and finishes it with the keyed completer <paramref name="completer"/>.
    /// <paramref name="confirmEmailEndpointName"/> is required so a single string still selects the confirm-email name.
    /// Pass <see langword="null"/> to use <see cref="AuthEndpointsEndpointNames.ConfirmEmail{TUser}"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeySignUpEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string completer,
        string? confirmEmailEndpointName)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(completer);
        return MapPasskeyRegisterCore<TUser>(
            endpoints,
            confirmEmailEndpointName,
            completer,
            ensureConfirmEmail: true,
            honorDefault: false,
            nameof(MapPasskeySignUpEndpoints),
            warn: true);
    }

    /// <summary>
    /// Maps <c>POST /passkeys/register/options</c>. Shared: options do not start a session.
    /// Antiforgery stays on, because a cookie session uses this one route.
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeyRegisterOptionsEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        EnsurePasskeyAndEmailSupport<TUser>(endpoints.ServiceProvider);
        WarnIfNeitherPasskeyModule<PasskeyRegisterOptionsEndpointsModule>(
            endpoints,
            "AddPasskeyRegisterOptionsEndpoints",
            nameof(MapPasskeyRegisterOptionsEndpoints));

        var group = endpoints.MapGroup("/passkeys");
        // Shared with every session, including cookie. Keep the token check on this one route.
        MapPasskeySignInRoutes<TUser>(
            group,
            confirmEmailEndpointName: AuthEndpointsEndpointNames.ConfirmEmail<TUser>(),
            nameof(MapPasskeyRegisterOptionsEndpoints),
            completer: null,
            honorDefault: false,
            AuthEndpointsSession.Cookie,
            requestOptions: false,
            registerOptions: true,
            register: false,
            loginRoute: false);
        return group;
    }

    internal static IEndpointConventionBuilder MapPasskeyAuthenticationCore<TUser>(
        IEndpointRouteBuilder endpoints,
        string completer,
        string mapMethod)
        where TUser : class, new()
    {
        EnsurePasskeyAndEmailSupport<TUser>(endpoints.ServiceProvider);
        SignInCompleterMap.EnsureSelected<TUser>(endpoints, completer, mapMethod);
        var group = endpoints.MapGroup("/passkeys");
        MapPasskeySignInRoutes<TUser>(
            group,
            confirmEmailEndpointName: AuthEndpointsEndpointNames.ConfirmEmail<TUser>(),
            mapMethod,
            completer,
            honorDefault: false,
            SessionForName(completer),
            requestOptions: true,
            registerOptions: false,
            register: false,
            loginRoute: true);
        return group;
    }

    internal static IEndpointConventionBuilder MapPasskeyRegisterCore<TUser>(
        IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName,
        string? completer,
        bool ensureConfirmEmail,
        bool honorDefault,
        string mapMethod,
        bool warn)
        where TUser : class, new()
    {
        EnsurePasskeyAndEmailSupport<TUser>(endpoints.ServiceProvider);
        if (warn)
        {
            WarnIfNeitherPasskeyModule<PasskeySignUpEndpointsModule>(
                endpoints,
                "AddPasskeySignUpEndpoints",
                mapMethod);
        }

        if (completer is null)
        {
            if (honorDefault)
            {
                SignInCompleterMap.EnsureConfiguredDefault<TUser>(
                    endpoints,
                    mapMethod,
                    LegacySignInCompleters.PasskeyWins<TUser>(endpoints.ServiceProvider));
            }
        }
        else
        {
            SignInCompleterMap.EnsureSelected<TUser>(endpoints, completer, mapMethod);
        }

        confirmEmailEndpointName ??= AuthEndpointsEndpointNames.ConfirmEmail<TUser>();
        var group = endpoints.MapGroup("/passkeys");
        MapPasskeySignInRoutes<TUser>(
            group,
            confirmEmailEndpointName,
            mapMethod,
            completer,
            honorDefault,
            SessionFor<TUser>(endpoints, completer, honorDefault),
            requestOptions: false,
            registerOptions: false,
            register: true,
            loginRoute: false);

        if (!ensureConfirmEmail)
        {
            return group;
        }

        var confirm = endpoints.MapConfirmEmailEndpoints<TUser>(confirmEmailEndpointName);
        return new CompositeEndpointConventionBuilder(group, confirm);
    }

    private static void WarnIfNeitherPasskeyModule<TSpecific>(
        IEndpointRouteBuilder endpoints,
        string addMethod,
        string mapMethod)
        where TSpecific : class
    {
        if (AuthEndpointsModules.IsRegistered<TSpecific>(endpoints.ServiceProvider)
            || AuthEndpointsModules.IsRegistered<PasskeyEndpointsModule>(endpoints.ServiceProvider))
        {
            return;
        }

        throw new InvalidOperationException($"Call {addMethod} before {mapMethod}.");
    }

    /// <summary>
    /// Built-in completer names select that session. A custom name keeps antiforgery.
    /// No name uses the configured default when it wins, otherwise Identity bearer.
    /// Identity bearer maps no <c>csrfToken</c> route, so that default omits antiforgery.
    /// </summary>
    private static AuthEndpointsSession SessionFor<TUser>(
        IEndpointRouteBuilder endpoints,
        string? completer,
        bool honorDefault)
        where TUser : class
    {
        if (!string.IsNullOrWhiteSpace(completer))
        {
            return SessionForName(completer);
        }

        if (honorDefault && !LegacySignInCompleters.PasskeyWins<TUser>(endpoints.ServiceProvider))
        {
            var configured = endpoints.ServiceProvider.GetService<IOptions<SignInCompletionOptions>>()?.Value.Default;
            if (!string.IsNullOrWhiteSpace(configured))
            {
                return SessionForName(configured);
            }
        }

        return AuthEndpointsSession.IdentityBearer;
    }

    private static AuthEndpointsSession SessionForName(string completer)
    {
        if (string.Equals(completer, SignInCompleters.Cookie, StringComparison.Ordinal))
        {
            return AuthEndpointsSession.Cookie;
        }

        if (string.Equals(completer, SignInCompleters.IdentityBearer, StringComparison.Ordinal))
        {
            return AuthEndpointsSession.IdentityBearer;
        }

        if (string.Equals(completer, SignInCompleters.Jwt, StringComparison.Ordinal))
        {
            return AuthEndpointsSession.Jwt;
        }

        return AuthEndpointsSession.Cookie;
    }

    /// <summary>
    /// Fail fast at map time: passkey endpoints are email-keyed and need a passkey store.
    /// </summary>
    internal static void EnsurePasskeyAndEmailSupport<TUser>(IServiceProvider services)
        where TUser : class
    {
        using var scope = services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();

        if (!userManager.SupportsUserPasskey)
        {
            throw new NotSupportedException(
                $"{nameof(MapPasskeyEndpoints)} requires a user store with passkey support.");
        }

        if (!userManager.SupportsUserEmail)
        {
            throw new NotSupportedException(
                $"{nameof(MapPasskeyEndpoints)} requires a user store with email support.");
        }
    }
}
