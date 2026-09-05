using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Passkey;

public static class PasskeyApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps passkey register, login, and credential management endpoints under <c>/passkeys</c>.
    /// </summary>
    /// <param name="confirmEmailEndpointName">
    /// Optional unique endpoint name for confirm-email link generation after passwordless register.
    /// Defaults to the same name as <c>MapIdentityManagementApi</c>. Required when that map
    /// used a custom name.
    /// </param>
    public static IEndpointConventionBuilder MapPasskeyEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        confirmEmailEndpointName ??= AuthEndpoints.Identity.IdentityApiEndpointRouteBuilderExtensions
            .DefaultConfirmEmailEndpointName<TUser>();
        var group = endpoints.MapGroup("/passkeys");

        group.MapPost("/creationOptions", PasskeyEndpoints<TUser>.CreationOptions)
            .WithSummary("Generate WebAuthn creation options for the signed-in user.")
            .RequireAuthorization()
            .RequireReauth()
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
            .RequireAntiforgery();

        group.MapPost("/requestOptions", PasskeyEndpoints<TUser>.RequestOptions)
            .WithSummary("Generate WebAuthn request options for passkey login.")
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
            .RequireAntiforgery();

        group.MapPost("/register/options", PasskeyEndpoints<TUser>.RegisterOptions)
            .WithSummary("Generate WebAuthn creation options for passwordless account registration.")
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
            .RequireAntiforgery();

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
                Default IdentityPasskeySignInCompleter: useCookies / useSessionCookies select the application cookie;
                otherwise Identity bearer tokens are issued. Register JwtPasskeySignInCompleter for Simple JWT
                (access token + refresh cookie). CSRF (antiforgery) is required.
                """)
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyRegisterPolicy)
            .RequireAntiforgery();

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
            .RequireAntiforgery();

        group.MapPost("/", PasskeyEndpoints<TUser>.AddPasskey)
            .WithSummary("Attest and store a passkey on the signed-in account.")
            .RequireAuthorization()
            .RequireReauth()
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyRegisterPolicy)
            .RequireAntiforgery();

        group.MapGet("/", PasskeyEndpoints<TUser>.ListPasskeys)
            .WithSummary("List passkeys for the signed-in user.")
            .RequireAuthorization();

        group.MapPatch("/", PasskeyEndpoints<TUser>.RenamePasskey)
            .WithSummary("Rename a passkey.")
            .RequireAuthorization()
            .RequireReauth()
            .RequireAntiforgery();

        group.MapDelete("/{credentialIdUrl}", PasskeyEndpoints<TUser>.DeletePasskey)
            .WithSummary("Remove a passkey from the signed-in account.")
            .RequireAuthorization()
            .RequireReauth()
            .RequireAntiforgery();

        return group;
    }
}
