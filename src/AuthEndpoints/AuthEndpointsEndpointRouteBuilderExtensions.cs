using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

public static class AuthEndpointsEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps everything <c>AddAuthEndpoints</c> registered under <paramref name="path"/>, finishing sign-in with
    /// <paramref name="session"/>: that session's sign-in and session routes
    /// (<see cref="AuthCompositionEndpointRouteBuilderExtensions.MapSignInEndpoints{TUser}"/>) and the shared routes
    /// (<see cref="AuthCompositionEndpointRouteBuilderExtensions.MapSharedAuthEndpoints{TUser}"/>).
    /// A route is mapped only when its feature was added, so registration and mapping cannot disagree.
    /// Because one session is mapped, <c>POST /passkeys/register/options</c> follows that session's antiforgery
    /// rule: an Identity bearer or JWT body-refresh session omits it, as the passkey ceremonies do.
    /// Returns the group, so conventions such as <c>WithTags</c> apply to every route.
    /// </summary>
    /// <remarks>
    /// For more than one session, call <c>MapSignInEndpoints</c> once per session prefix and
    /// <c>MapSharedAuthEndpoints</c> once, instead of calling this method twice.
    /// </remarks>
    public static RouteGroupBuilder MapAuthEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string path,
        AuthEndpointsSession session)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(path);
        if (path.Length > 0 && !path.StartsWith('/'))
        {
            throw new ArgumentException("Path must be empty or a rooted path such as \"/auth\".", nameof(path));
        }

        if (endpoints.ServiceProvider.GetService<AuthEndpointsRegistration>() is null)
        {
            throw new InvalidOperationException("Call AddAuthEndpoints before MapAuthEndpoints.");
        }

        // Validates the options here rather than at the first request.
        _ = endpoints.ServiceProvider.GetRequiredService<IOptions<AuthEndpointsOptions>>().Value;

        var features = AuthEndpointsFeatures.For(endpoints);
        switch (session)
        {
            case AuthEndpointsSession.Cookie:
                break;
            case AuthEndpointsSession.Jwt:
                AuthEndpointsFeatures.Require(features.Jwt, "AddJwt on AddAuthEndpoints", "MapAuthEndpoints with AuthEndpointsSession.Jwt");
                break;
            case AuthEndpointsSession.IdentityBearer:
                AuthEndpointsFeatures.Require(
                    features.Sessions.IdentityBearer,
                    "AddIdentityBearer on AddAuthEndpoints",
                    "MapAuthEndpoints with AuthEndpointsSession.IdentityBearer");
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(session), session, "Unknown sign-in session.");
        }

        var group = endpoints.MapGroup(path);
        group.MapSignInEndpoints<TUser>(session);
        AuthCompositionEndpointRouteBuilderExtensions.MapSharedAuthEndpointsCore<TUser>(group, sharedPath: null, session);
        return group;
    }
}
