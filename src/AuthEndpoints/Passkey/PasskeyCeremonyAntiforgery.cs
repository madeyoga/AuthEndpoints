using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Passkey;

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
