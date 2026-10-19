using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.ReAuth;

public static class ReAuthApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps reauthentication endpoints onto the current route group
    /// (<c>/confirmIdentity</c>, <c>/confirmIdentity/passkeyOptions</c>, <c>/manage/authMethods</c>).
    /// <c>POST /confirmIdentity/emailCode/send</c> is included when <c>AddEmailCodeSendEndpoints</c>
    /// or <c>AddEmailCodeEndpoints</c> was called. <c>AddEmailCodeSignInEndpoints</c> alone leaves it unmapped.
    /// </summary>
    public static IEndpointConventionBuilder MapReAuthEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        bool requireAntiforgery = false)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        if (endpoints.ServiceProvider.GetService<ReAuthSchemeMarker>() is null)
        {
            throw new InvalidOperationException("Call AddReAuthScheme before MapReAuthEndpoints.");
        }

        var group = endpoints.MapGroup("");
        IdentityEndpointRoutes.MapConfirmIdentity<TUser>(group, requireAntiforgery, nameof(MapReAuthEndpoints));
        IdentityEndpointRoutes.MapEmailCodeReAuthSend<TUser>(group, requireAntiforgery, nameof(MapReAuthEndpoints));
        IdentityEndpointRoutes.MapPasskeyOptions<TUser>(group, requireAntiforgery, nameof(MapReAuthEndpoints));
        IdentityEndpointRoutes.MapAuthMethods<TUser>(group, nameof(MapReAuthEndpoints));
        return group;
    }
}
