using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

public static class PasswordAuthEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the password facade under <see cref="PasswordAuthOptions.Path"/> (default <c>/auth</c>):
    /// register, login or JWT <c>POST /create</c>, forgotPassword, resetPassword,
    /// the session routes, confirmEmail, resendConfirmationEmail, and account management
    /// (<c>/manage/info</c>, <c>/manage/2fa</c>, <c>/manage/authMethods</c>, <c>/manage/password</c>, <c>/confirmIdentity</c>).
    /// Passkey sign-in and management are included when <see cref="PasskeyScenarioOptions.ServerDomain"/> is set.
    /// Email-code sign-in and external sign-in are not mapped.
    /// Antiforgery stays on the anonymous passkey ceremonies for a cookie session and for JWT cookie refresh.
    /// JWT body refresh omits it on those ceremonies, and omits csrfToken.
    /// Management routes keep antiforgery.
    /// </summary>
    public static IEndpointConventionBuilder MapPasswordAuth<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        if (endpoints.ServiceProvider.GetService<PasswordAuthRegistration>() is null)
        {
            throw new InvalidOperationException(
                "AddPasswordAuth<TUser, TContext> was not called before MapPasswordAuth<TUser>.");
        }

        // Validates the options, including a later Configure that disagrees with registration.
        _ = endpoints.ServiceProvider.GetRequiredService<IOptions<PasswordAuthOptions>>().Value;
        var registration = endpoints.ServiceProvider.GetRequiredService<PasswordAuthRegistration>();
        var group = endpoints.MapGroup(registration.Path);
        var builders = new List<IEndpointConventionBuilder>
        {
            group.MapPasswordSignUpEndpoints<TUser>(),
        };

        if (registration.Session == AuthEndpointsSession.Jwt)
        {
            builders.Add(group.MapJwtPasswordEndpoints<TUser>());
        }
        else
        {
            builders.Add(group.MapPasswordSignInEndpoints<TUser>(AuthEndpointsSession.Cookie));
        }

        builders.Add(group.MapPasswordRecoveryEndpoints<TUser>());

        if (registration.Session == AuthEndpointsSession.Jwt)
        {
            builders.Add(group.MapJwtSessionEndpoints<TUser>());
        }
        else
        {
            builders.Add(group.MapCookieSessionEndpoints<TUser>());
        }

        builders.Add(group.MapAccountManagementEndpoints<TUser>());

        if (registration.PasskeysMapped)
        {
            builders.Add(group.MapPasskeySignInEndpoints<TUser>(registration.Session));
            builders.Add(group.MapPasskeyManagementEndpoints<TUser>());
        }

        return new CompositeEndpointConventionBuilder(builders.ToArray());
    }
}
