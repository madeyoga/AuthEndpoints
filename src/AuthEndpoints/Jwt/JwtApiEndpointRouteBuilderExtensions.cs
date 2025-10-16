using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Jwt;

public static class JwtApiEndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapJwtApi<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var routeGroup = endpoints.MapGroup("").WithTags("Jwt");

        routeGroup.MapPost("/create", JwtEndpoints<TUser>.Create);
        routeGroup.MapPost("/refresh", JwtEndpoints<TUser>.Refresh);
        routeGroup.MapGet("/verify", JwtEndpoints<TUser>.Verify);

        return routeGroup;
    }
}
