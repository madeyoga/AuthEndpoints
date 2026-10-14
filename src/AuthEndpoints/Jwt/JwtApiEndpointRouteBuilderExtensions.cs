using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Jwt;

public static class JwtApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps JWT auth endpoints (create, refresh, verify, logout, csrfToken).
    /// Call <see cref="ServiceCollectionExtensions.AddJwtEndpoints{TUser, TContext}"/>,
    /// <c>UseRateLimiter()</c>, and <c>UseAntiforgery()</c>.
    /// Pair with <c>MapIdentityManagementApi</c> for register/manage.
    /// </summary>
    public static IEndpointConventionBuilder MapJwtAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var create = endpoints.MapJwtPasswordEndpoints<TUser>();
        var session = endpoints.MapJwtSessionEndpoints<TUser>();
        return new CompositeEndpointConventionBuilder(create, session);
    }

    /// <summary>
    /// Maps password JWT <c>POST /create</c>.
    /// </summary>
    public static IEndpointConventionBuilder MapJwtPasswordEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        AuthEndpointsModules.WarnIfMissing<JwtEndpointsModule>(
            endpoints,
            "AddJwtEndpoints",
            "MapJwtPasswordEndpoints");

        var routeGroup = endpoints.MapGroup("");
        routeGroup.MapPost("/create", JwtEndpoints<TUser>.Create)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
            .Track(endpoints, nameof(MapJwtPasswordEndpoints));
        PasswordSignInMap.Mark(endpoints.ServiceProvider);
        return routeGroup;
    }

    /// <summary>
    /// Maps JWT <c>POST /refresh</c>, <c>GET /verify</c>, <c>POST /logout</c>, and <c>GET /csrfToken</c>.
    /// </summary>
    public static IEndpointConventionBuilder MapJwtSessionEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        AuthEndpointsModules.WarnIfMissing<JwtEndpointsModule>(
            endpoints,
            "AddJwtEndpoints",
            "MapJwtSessionEndpoints");

        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapPost("/refresh", JwtEndpoints<TUser>.Refresh)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
            .RequireAntiforgery()
            .Track(endpoints, nameof(MapJwtSessionEndpoints));

        routeGroup.MapGet("/verify", JwtEndpoints<TUser>.Verify)
            .Track(endpoints, nameof(MapJwtSessionEndpoints));

        routeGroup.MapPost("/logout", JwtEndpoints<TUser>.Logout)
            .RequireAntiforgery()
            .Track(endpoints, nameof(MapJwtSessionEndpoints));

        routeGroup.MapGet("/csrfToken", JwtEndpoints<TUser>.GetAntiforgeryToken)
            .Track(endpoints, nameof(MapJwtSessionEndpoints));

        return routeGroup;
    }
}
