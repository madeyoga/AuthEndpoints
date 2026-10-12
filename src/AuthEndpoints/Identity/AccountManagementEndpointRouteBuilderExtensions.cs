using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

public static class AccountManagementEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps signed-in account routes: <c>/manage/info</c>, <c>/manage/2fa</c>, <c>/manage/authMethods</c>,
    /// and <c>/confirmIdentity</c>. <c>POST /confirmIdentity/passkeyOptions</c> is mapped when
    /// <c>AddPasskeyEndpoints</c> was called. Also maps confirm-email when that name is not mapped yet.
    /// </summary>
    public static IEndpointConventionBuilder MapAccountManagementEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        return MapAccountManagementEndpoints<TUser>(endpoints, confirmEmailEndpointName, alwaysMapPasskeyOptions: false);
    }

    internal static IEndpointConventionBuilder MapAccountManagementEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName,
        bool alwaysMapPasskeyOptions)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        AuthEndpointsModules.WarnIfMissing<AccountManagementEndpointsModule>(
            endpoints,
            "AddAccountManagementEndpoints",
            "MapAccountManagementEndpoints");

        confirmEmailEndpointName ??= AuthEndpointsEndpointNames.ConfirmEmail<TUser>();
        ConfirmEmailEndpointRouteBuilderExtensions.EnsureConfirmEmailMapped<TUser>(endpoints, confirmEmailEndpointName);

        var group = endpoints.MapGroup("");
        IdentityEndpointRoutes.MapConfirmIdentity<TUser>(group, requireAntiforgery: true);
        if (alwaysMapPasskeyOptions || AuthEndpointsModules.IsRegistered<PasskeyEndpointsModule>(endpoints.ServiceProvider))
        {
            IdentityEndpointRoutes.MapPasskeyOptions<TUser>(group, requireAntiforgery: true);
        }

        IdentityEndpointRoutes.MapAuthMethods<TUser>(group);
        IdentityEndpointRoutes.MapManageInfoAndTwoFactor<TUser>(group, confirmEmailEndpointName);
        return group;
    }
}
