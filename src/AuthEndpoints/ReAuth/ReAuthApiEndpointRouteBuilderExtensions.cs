using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.ReAuth;

public static class ReAuthApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps reauthentication endpoints onto the current route group
    /// (<c>/confirmIdentity</c>, <c>/confirmIdentity/passkeyOptions</c>, <c>/manage/authMethods</c>).
    /// </summary>
    public static IEndpointConventionBuilder MapReAuthEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        bool requireAntiforgery = false)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var group = endpoints.MapGroup("");
        IdentityEndpointRoutes.MapConfirmIdentity<TUser>(group, requireAntiforgery, nameof(MapReAuthEndpoints));
        IdentityEndpointRoutes.MapPasskeyOptions<TUser>(group, requireAntiforgery, nameof(MapReAuthEndpoints));
        IdentityEndpointRoutes.MapAuthMethods<TUser>(group, nameof(MapReAuthEndpoints));
        return group;
    }
}
