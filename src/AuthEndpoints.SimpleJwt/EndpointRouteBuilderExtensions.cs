#if NET7_0_OR_GREATER
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.SimpleJwt;

public static class EndpointRouteBuilderExtensions
{
    public static RouteGroupBuilder MapSimpleJwtApi<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");

        routeGroup.MapPost($"/create", JwtEndpointDefinition<TUser>.Create);
        routeGroup.MapPost($"/refresh", JwtEndpointDefinition<TUser>.Refresh);
        routeGroup.MapGet($"/verify", JwtEndpointDefinition<TUser>.Verify).RequireAuthorization();

        return routeGroup;
    }
}
#endif
