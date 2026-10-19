using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Passkey;

/// <summary>
/// Passkey ceremonies keep antiforgery when the session carries an ambient credential.
/// A cookie session does. JWT does when <see cref="JwtSessionOptions.RefreshTokenTransport"/>
/// is <see cref="RefreshTokenTransport.Cookie"/>. Identity bearer does not, and JWT body
/// refresh does not. Identity bearer maps no <c>csrfToken</c> route. JWT body refresh maps none.
/// </summary>
internal static class PasskeyCeremonyAntiforgery
{
    public static bool Required(AuthEndpointsSession session, RefreshTokenTransport refreshTokenTransport)
    {
        return session switch
        {
            AuthEndpointsSession.Cookie => true,
            AuthEndpointsSession.IdentityBearer => false,
            AuthEndpointsSession.Jwt => refreshTokenTransport == RefreshTokenTransport.Cookie,
            _ => throw new ArgumentOutOfRangeException(nameof(session), session, "Unknown sign-in session."),
        };
    }

    public static RouteHandlerBuilder RequirePasskeyCeremonyAntiforgery(
        this RouteHandlerBuilder builder,
        IEndpointRouteBuilder endpoints,
        AuthEndpointsSession session)
    {
        var transport = endpoints.ServiceProvider.GetService<IOptions<JwtSessionOptions>>()?.Value.RefreshTokenTransport
            ?? RefreshTokenTransport.Cookie;
        return Required(session, transport)
            ? builder.RequireAntiforgery()
            : builder;
    }
}
