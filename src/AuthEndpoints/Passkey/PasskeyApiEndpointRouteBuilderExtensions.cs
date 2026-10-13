using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Passkey;

public static class PasskeyApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps passkey register, login, and credential management endpoints under <c>/passkeys</c>.
    /// This is <see cref="MapPasskeySignInEndpoints{TUser}"/> without auto-mapping confirm-email,
    /// plus <see cref="MapPasskeyManagementEndpoints{TUser}"/>, on one <c>/passkeys</c> group.
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
            honorDefault: false);
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
        WarnIfPasskeysMissing(endpoints, nameof(MapPasskeySignInEndpoints));
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
            honorDefault: completer is null);
        var confirm = endpoints.MapConfirmEmailEndpoints<TUser>(confirmEmailEndpointName);
        return new CompositeEndpointConventionBuilder(group, confirm);
    }

    /// <summary>
    /// Maps signed-in passkey credential management under <c>/passkeys</c>
    /// (<c>creationOptions</c>, <c>POST /</c>, <c>GET /</c>, <c>PATCH /</c>, <c>DELETE /{credentialIdUrl}</c>).
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeyManagementEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        EnsurePasskeyAndEmailSupport<TUser>(endpoints.ServiceProvider);
        WarnIfPasskeysMissing(endpoints, nameof(MapPasskeyManagementEndpoints));

        var group = endpoints.MapGroup("/passkeys");
        MapPasskeyRoutes<TUser>(
            group,
            confirmEmailEndpointName: null,
            nameof(MapPasskeyManagementEndpoints),
            signIn: false,
            management: true,
            completer: null,
            honorDefault: false);
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
        AuthEndpointsModules.WarnIfMissing<PasskeyEndpointsModule>(endpoints, "AddPasskeyEndpoints", mapMethod);
    }

    private static void MapPasskeyRoutes<TUser>(
        IEndpointRouteBuilder group,
        string? confirmEmailEndpointName,
        string mapMethod,
        bool signIn,
        bool management,
        string? completer,
        bool honorDefault)
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
                .RequireAntiforgery()
                .Track(group, mapMethod);
        }

        if (signIn)
        {
            MapPasskeySignInRoutes<TUser>(group, confirmEmailEndpointName!, mapMethod, completer, honorDefault);
        }

        if (!management || secured is null)
        {
            return;
        }

        secured.MapPost("/", PasskeyEndpoints<TUser>.AddPasskey)
            .WithSummary("Attest and store a passkey on the signed-in account.")
            .RequireReauth()
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyRegisterPolicy)
            .RequireAntiforgery()
            .Track(group, mapMethod);

        secured.MapGet("/", PasskeyEndpoints<TUser>.ListPasskeys)
            .WithSummary("List passkeys for the signed-in user.")
            .Track(group, mapMethod);

        secured.MapPatch("/", PasskeyEndpoints<TUser>.RenamePasskey)
            .WithSummary("Rename a passkey.")
            .WithDescription("Trims the name. A name longer than 200 characters is rejected.")
            .RequireReauth()
            .RequireAntiforgery()
            .Track(group, mapMethod);

        secured.MapDelete("/{credentialIdUrl}", PasskeyEndpoints<TUser>.DeletePasskey)
            .WithSummary("Remove a passkey from the signed-in account.")
            .WithDescription("""
                Refuses with a validation problem when this passkey is the user's only sign-in method
                (no password and no external login).
                """)
            .RequireReauth()
            .RequireAntiforgery()
            .Track(group, mapMethod);
    }

    private static void MapPasskeySignInRoutes<TUser>(
        IEndpointRouteBuilder group,
        string confirmEmailEndpointName,
        string mapMethod,
        string? completer,
        bool honorDefault)
        where TUser : class, new()
    {
        group.MapPost("/requestOptions", PasskeyEndpoints<TUser>.RequestOptions)
            .WithSummary("Generate WebAuthn request options for passkey login.")
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
            .RequireAntiforgery()
            .Track(group, mapMethod);

        group.MapPost("/register/options", PasskeyEndpoints<TUser>.RegisterOptions)
            .WithSummary("Generate WebAuthn creation options for passwordless account registration.")
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
            .RequireAntiforgery()
            .Track(group, mapMethod);

        var register = group.MapPost("/register", (
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
                CSRF (antiforgery) is required.
                """)
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyRegisterPolicy)
            .RequireAntiforgery()
            .Track(group, mapMethod);

        var login = group.MapPost("/login", PasskeyEndpoints<TUser>.Login)
            .WithSummary("Sign in with a passkey assertion.")
            .WithDescription("""
                Completes sign-in via IPasskeySignInCompleter unless the map selected a session or completer.
                Default IdentityPasskeySignInCompleter:
                ?useCookies=true → persistent application cookie;
                ?useSessionCookies=true → session application cookie;
                neither → Identity bearer token (AccessTokenResponse).
                Pass session: AuthEndpointsSession.Jwt or completer: SignInCompleters.Jwt for Simple JWT
                (access token + refresh cookie).
                CSRF (antiforgery) is required for the WebAuthn ceremony.
                """)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
            .RequireAntiforgery()
            .Track(group, mapMethod);

        if (completer is not null)
        {
            var selection = new SignInCompleterSelection(completer);
            register.WithMetadata(selection);
            login.WithMetadata(selection);
        }
        else if (honorDefault)
        {
            var honor = new HonorSignInCompletionDefault();
            register.WithMetadata(honor);
            login.WithMetadata(honor);
        }
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
