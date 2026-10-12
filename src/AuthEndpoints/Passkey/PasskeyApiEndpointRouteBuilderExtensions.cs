using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
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
        MapPasskeyRoutes<TUser>(group, confirmEmailEndpointName, nameof(MapPasskeyEndpoints), signIn: true, management: true);
        return group;
    }

    /// <summary>
    /// Maps passkey sign-up and sign-in under <c>/passkeys</c>
    /// (<c>requestOptions</c>, <c>login</c>, <c>register/options</c>, <c>register</c>).
    /// Maps confirm-email on the parent builder when that endpoint name is not mapped yet.
    /// The returned builder includes that confirm-email group, so later conventions apply to confirm and resend.
    /// When the name is already mapped, <see cref="ConfirmEmailEndpointRouteBuilderExtensions.MapConfirmEmailEndpoints{TUser}"/>
    /// contributes a no-op builder and those conventions do not reach the existing route.
    /// </summary>
    public static IEndpointConventionBuilder MapPasskeySignInEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        EnsurePasskeyAndEmailSupport<TUser>(endpoints.ServiceProvider);
        WarnIfPasskeysMissing(endpoints, nameof(MapPasskeySignInEndpoints));

        confirmEmailEndpointName ??= AuthEndpointsEndpointNames.ConfirmEmail<TUser>();
        var group = endpoints.MapGroup("/passkeys");
        MapPasskeyRoutes<TUser>(group, confirmEmailEndpointName, nameof(MapPasskeySignInEndpoints), signIn: true, management: false);
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
        MapPasskeyRoutes<TUser>(group, confirmEmailEndpointName: null, nameof(MapPasskeyManagementEndpoints), signIn: false, management: true);
        return group;
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
        bool management)
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
            MapPasskeySignInRoutes<TUser>(group, confirmEmailEndpointName!, mapMethod);
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

    private static void MapPasskeySignInRoutes<TUser>(IEndpointRouteBuilder group, string confirmEmailEndpointName, string mapMethod)
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

        group.MapPost("/register", (
            [FromBody] PasskeyRegisterRequest request,
            [FromQuery] bool? useCookies,
            [FromQuery] bool? useSessionCookies,
            HttpContext httpContext,
            UserManager<TUser> userManager,
            IUserStore<TUser> userStore,
            SignInManager<TUser> signInManager,
            IPasskeySignInCompleter<TUser> completer,
            CancellationToken cancellationToken) => PasskeyEndpoints<TUser>.Register(
                request,
                useCookies,
                useSessionCookies,
                httpContext,
                userManager,
                userStore,
                signInManager,
                completer,
                confirmEmailEndpointName,
                cancellationToken))
            .WithSummary("Create a passwordless account and store the attested passkey.")
            .WithDescription("""
                After a successful user create, sends the same confirmation email as password register.
                Sign-in is completed by IPasskeySignInCompleter.
                Default IdentityPasskeySignInCompleter: useCookies / useSessionCookies select the application cookie
                and the body is credentialId; otherwise Identity bearer tokens are issued and that token body is the response.
                Register JwtPasskeySignInCompleter for Simple JWT (access token + refresh cookie, no credentialId).
                When sign-in is not allowed, the body is credentialId and no session is issued.
                CSRF (antiforgery) is required.
                """)
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyRegisterPolicy)
            .RequireAntiforgery()
            .Track(group, mapMethod);

        group.MapPost("/login", PasskeyEndpoints<TUser>.Login)
            .WithSummary("Sign in with a passkey assertion.")
            .WithDescription("""
                Completes sign-in via IPasskeySignInCompleter.
                Default IdentityPasskeySignInCompleter:
                ?useCookies=true → persistent application cookie;
                ?useSessionCookies=true → session application cookie;
                neither → Identity bearer token (AccessTokenResponse).
                Register JwtPasskeySignInCompleter for Simple JWT (access token + refresh cookie).
                CSRF (antiforgery) is required for the WebAuthn ceremony.
                """)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
            .RequireAntiforgery()
            .Track(group, mapMethod);
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
