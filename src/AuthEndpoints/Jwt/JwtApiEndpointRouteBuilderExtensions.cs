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

        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapPost("/create", JwtEndpoints<TUser>.Create)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy);

        routeGroup.MapPost("/refresh", JwtEndpoints<TUser>.Refresh)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
            .RequireAntiforgery();

        routeGroup.MapGet("/verify", JwtEndpoints<TUser>.Verify);

        routeGroup.MapPost("/logout", JwtEndpoints<TUser>.Logout)
            .RequireAntiforgery();

        routeGroup.MapGet("/csrfToken", JwtEndpoints<TUser>.GetAntiforgeryToken);

        return routeGroup;
    }
}
