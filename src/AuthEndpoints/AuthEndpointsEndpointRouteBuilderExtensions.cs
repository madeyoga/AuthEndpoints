using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

public static class AuthEndpointsEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the opinionated auth surface: Identity management plus the configured sign-in stack at
    /// <see cref="AuthEndpointsOptions.IdentityPath"/>, passkeys at
    /// <see cref="AuthEndpointsOptions.PasskeyPath"/> when enabled, and JWT when
    /// <see cref="AuthEndpointsJwtOptions.Enabled"/> is true.
    /// Sign-in is <see cref="AuthEndpointsSignIn.Cookie"/> (<c>LoginCookie</c>) or
    /// <see cref="AuthEndpointsSignIn.IdentityBearer"/> (Identity <c>Login</c>).
    /// For a single module use <c>MapIdentityManagementApi</c>, <c>MapCookieAuthEndpoints</c>,
    /// <c>MapBearerAuthEndpoints</c>, <c>MapPasskeyEndpoints</c>, or <c>MapJwtAuthEndpoints</c>.
    /// This facade ignores <see cref="SignInCompletionOptions.Default"/> and keeps the 3.4.1 sign-in handlers,
    /// including email-code verify. It leaves <c>POST /confirmIdentity/emailCode/send</c> and
    /// <c>POST /manage/password</c> unmapped, and <c>authMethods.emailCode</c> stays false.
    /// </summary>
    public static IEndpointConventionBuilder MapAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<AuthEndpointsOptions>>().Value;
        return MapAuthEndpointsCore<TUser>(endpoints, options, options.SignIn);
    }

    private static IEndpointConventionBuilder MapAuthEndpointsCore<TUser>(
        IEndpointRouteBuilder endpoints,
        AuthEndpointsOptions options,
        AuthEndpointsSignIn signIn)
        where TUser : class, new()
    {
        var identity = endpoints.MapGroup(options.IdentityPath).WithTags("Identity");
        identity.MapIdentityManagementApiPreserving3x<TUser>();

        if (signIn == AuthEndpointsSignIn.IdentityBearer)
        {
            identity.MapBearerAuthEndpoints<TUser>();
        }
        else
        {
            identity.MapCookieAuthEndpoints<TUser>();
        }

        if (options.EmailCode.Enabled)
        {
            identity.MapEmailCodeEndpointsPreserving3x<TUser>();
        }

        if (options.Passkeys.Enabled)
        {
            endpoints.MapGroup(options.PasskeyPath)
                .MapPasskeyEndpoints<TUser>()
                .WithTags("Passkeys");
        }

        if (options.Jwt.Enabled)
        {
            endpoints.MapGroup(options.Jwt.Path)
                .MapJwtAuthEndpoints<TUser>()
                .WithTags("Jwt");
        }

        return identity;
    }
}
