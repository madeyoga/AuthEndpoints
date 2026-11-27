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
        var features = AuthEndpointsFeatures.For(endpoints);

        if (!features.Password.CanSignIn
            && !features.EmailCode.CanSignIn
            && !features.Passkeys.CanAuthenticate
            && !features.Passkeys.CanSignUp)
        {
            AuthEndpointsModules.LogNoSignInModule(endpoints);
        }

        if (features.Password.CanSignIn)
        {
            builders.Add(session == AuthEndpointsSession.Jwt
                ? endpoints.MapJwtPasswordEndpoints<TUser>()
                : endpoints.MapPasswordSignInEndpoints<TUser>(session));
        }

        if (features.EmailCode.CanSignIn)
        {
            builders.Add(endpoints.MapEmailCodeSignInEndpoints<TUser>(session));
        }

        if (features.Passkeys.CanAuthenticate)
        {
            builders.Add(PasskeyApiEndpointRouteBuilderExtensions.MapPasskeyAuthenticationCore<TUser>(
                endpoints,
                completer,
                nameof(MapSignInEndpoints)));
        }

        if (features.Passkeys.CanSignUp)
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
        var features = AuthEndpointsFeatures.For(target);

        if (features.Password.CanSignUp)
        {
            builders.Add(target.MapPasswordSignUpEndpoints<TUser>());
            mappedConfirm = true;
        }

        if (features.Password.CanRecover)
        {
            builders.Add(target.MapPasswordRecoveryEndpoints<TUser>());
        }

        if (features.EmailCode.CanSend)
        {
            builders.Add(target.MapEmailCodeSendEndpoints<TUser>());
        }

        if (features.Passkeys.CanRequestRegisterOptions)
        {
            builders.Add(target.MapPasskeyRegisterOptionsEndpoints<TUser>());
        }

        if (features.Passkeys.CanManage)
        {
            builders.Add(target.MapPasskeyManagementEndpoints<TUser>());
        }

        if (features.AccountManagement)
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
