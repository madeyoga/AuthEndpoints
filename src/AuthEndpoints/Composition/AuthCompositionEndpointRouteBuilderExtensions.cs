using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints;

public static class AuthCompositionEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the per-session routes for the modules that are registered, plus that session's own routes.
    /// Password login is <c>POST /login</c> for cookie and Identity bearer, and <c>POST /create</c> for JWT.
    /// Email-code verify, passkey request options, passkey login, and passkey register are included when those
    /// modules are registered. Logs a warning when none of those sign-in modules are registered.
    /// Passkey register does not map confirm-email; call <see cref="MapSharedAuthEndpoints{TUser}"/> or the link
    /// targets a missing route. Shared routes stay on <see cref="MapSharedAuthEndpoints{TUser}"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapSignInEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        AuthEndpointsSession session)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var builders = new List<IEndpointConventionBuilder>();
        var completer = SignInCompleterMap.FromSession(session);
        var passkeyBundle = Registered<PasskeyEndpointsModule>(endpoints);
        var passkeySignIn = passkeyBundle || Registered<PasskeySignInEndpointsModule>(endpoints);
        var passkeySignUp = passkeyBundle || Registered<PasskeySignUpEndpointsModule>(endpoints);

        if (!Registered<PasswordSignInEndpointsModule>(endpoints)
            && !Registered<EmailCodeSignInEndpointsModule>(endpoints)
            && !passkeySignIn
            && !passkeySignUp)
        {
            AuthEndpointsModules.Log(
                endpoints,
                "MapSignInEndpoints mapped no sign-in method. Call AddPasswordSignInEndpoints, AddEmailCodeSignInEndpoints, AddPasskeySignInEndpoints, or AddPasskeySignUpEndpoints before MapSignInEndpoints.");
        }

        if (Registered<PasswordSignInEndpointsModule>(endpoints))
        {
            builders.Add(session == AuthEndpointsSession.Jwt
                ? endpoints.MapJwtPasswordEndpoints<TUser>()
                : endpoints.MapPasswordSignInEndpoints<TUser>(session));
        }

        if (Registered<EmailCodeSignInEndpointsModule>(endpoints))
        {
            builders.Add(endpoints.MapEmailCodeSignInEndpoints<TUser>(session));
        }

        if (passkeySignIn)
        {
            builders.Add(PasskeyApiEndpointRouteBuilderExtensions.MapPasskeyAuthenticationCore<TUser>(
                endpoints,
                completer,
                nameof(MapSignInEndpoints)));
        }

        if (passkeySignUp)
        {
            builders.Add(PasskeyApiEndpointRouteBuilderExtensions.MapPasskeyRegisterCore<TUser>(
                endpoints,
                confirmEmailEndpointName: null,
                completer,
                ensureConfirmEmail: false,
                honorDefault: false,
                nameof(MapSignInEndpoints),
                warn: false));
        }

        builders.Add(session switch
        {
            AuthEndpointsSession.Cookie => endpoints.MapCookieSessionEndpoints<TUser>(),
            AuthEndpointsSession.IdentityBearer => endpoints.MapBearerSessionEndpoints<TUser>(),
            AuthEndpointsSession.Jwt => endpoints.MapJwtSessionEndpoints<TUser>(),
            _ => throw new ArgumentOutOfRangeException(nameof(session), session, "Unknown sign-in session."),
        });

        return Combine(builders);
    }

    /// <summary>
    /// Maps shared routes once: password sign-up and recovery, email-code send, passkey registration options,
    /// passkey management, account management, and confirm-email. A route is included only when its
    /// <c>Add*</c> module is registered, except confirm-email, which is always ensured.
    /// Pass <paramref name="sharedPath"/> to mount them on that prefix. Null or empty mounts them on
    /// <paramref name="endpoints"/> (the app root when called on the application builder).
    /// </summary>
    public static IEndpointConventionBuilder MapSharedAuthEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? sharedPath = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var target = string.IsNullOrWhiteSpace(sharedPath)
            ? endpoints
            : endpoints.MapGroup(sharedPath);
        var builders = new List<IEndpointConventionBuilder>();
        var mappedConfirm = false;

        if (Registered<PasswordSignUpEndpointsModule>(target))
        {
            builders.Add(target.MapPasswordSignUpEndpoints<TUser>());
            mappedConfirm = true;
        }

        if (Registered<PasswordRecoveryEndpointsModule>(target))
        {
            builders.Add(target.MapPasswordRecoveryEndpoints<TUser>());
        }

        if (Registered<EmailCodeSendEndpointsModule>(target))
        {
            builders.Add(target.MapEmailCodeSendEndpoints<TUser>());
        }

        if (Registered<PasskeyEndpointsModule>(target) || Registered<PasskeyRegisterOptionsEndpointsModule>(target))
        {
            builders.Add(target.MapPasskeyRegisterOptionsEndpoints<TUser>());
        }

        if (Registered<PasskeyEndpointsModule>(target) || Registered<PasskeyManagementEndpointsModule>(target))
        {
            builders.Add(target.MapPasskeyManagementEndpoints<TUser>());
        }

        if (Registered<AccountManagementEndpointsModule>(target))
        {
            builders.Add(target.MapAccountManagementEndpoints<TUser>());
            mappedConfirm = true;
        }

        if (!mappedConfirm)
        {
            builders.Add(target.MapConfirmEmailEndpoints<TUser>());
        }

        return Combine(builders);
    }

    private static bool Registered<TModule>(IEndpointRouteBuilder endpoints)
        where TModule : class
    {
        return AuthEndpointsModules.IsRegistered<TModule>(endpoints.ServiceProvider);
    }

    private static IEndpointConventionBuilder Combine(List<IEndpointConventionBuilder> builders)
    {
        return builders.Count switch
        {
            0 => EmptyEndpointConventionBuilder.Instance,
            1 => builders[0],
            _ => new CompositeEndpointConventionBuilder(builders.ToArray()),
        };
    }
}
