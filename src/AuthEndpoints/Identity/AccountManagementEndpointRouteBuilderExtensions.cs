using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

public static class AccountManagementEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps signed-in account routes: <c>/manage/info</c>, <c>/manage/2fa</c>, <c>/manage/authMethods</c>,
    /// and <c>/confirmIdentity</c>. <c>POST /confirmIdentity/emailCode/send</c> is mapped when
    /// <c>AddEmailCodeEndpoints</c> was called. <c>POST /confirmIdentity/passkeyOptions</c> is mapped when
    /// <c>AddPasskeyEndpoints</c> was called. Also maps confirm-email when that name is not mapped yet.
    /// The returned builder includes that confirm-email group, so later conventions apply to confirm and resend.
    /// When the name is already mapped, <see cref="ConfirmEmailEndpointRouteBuilderExtensions.MapConfirmEmailEndpoints{TUser}"/>
    /// contributes a no-op builder and those conventions do not reach the existing route.
    /// </summary>
    public static IEndpointConventionBuilder MapAccountManagementEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        return MapAccountManagementEndpoints<TUser>(
            endpoints,
            confirmEmailEndpointName,
            alwaysMapPasskeyOptions: false,
            emailCodeReAuth: true);
    }

    internal static IEndpointConventionBuilder MapAccountManagementEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName,
        bool alwaysMapPasskeyOptions,
        bool emailCodeReAuth)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        AuthEndpointsModules.WarnIfMissing<AccountManagementEndpointsModule>(
            endpoints,
            "AddAccountManagementEndpoints",
            "MapAccountManagementEndpoints");

        confirmEmailEndpointName ??= AuthEndpointsEndpointNames.ConfirmEmail<TUser>();
        var confirm = endpoints.MapConfirmEmailEndpoints<TUser>(confirmEmailEndpointName);

        var group = endpoints.MapGroup("");
        const string mapMethod = nameof(MapAccountManagementEndpoints);
        IdentityEndpointRoutes.MapConfirmIdentity<TUser>(group, requireAntiforgery: true, mapMethod);
        if (emailCodeReAuth)
        {
            IdentityEndpointRoutes.MapEmailCodeReAuthSend<TUser>(group, requireAntiforgery: true, mapMethod);
        }

        if (alwaysMapPasskeyOptions || AuthEndpointsModules.IsRegistered<PasskeyEndpointsModule>(endpoints.ServiceProvider))
        {
            IdentityEndpointRoutes.MapPasskeyOptions<TUser>(group, requireAntiforgery: true, mapMethod);
        }

        IdentityEndpointRoutes.MapAuthMethods<TUser>(group, mapMethod, includeEmailCode: emailCodeReAuth);
        IdentityEndpointRoutes.MapManageInfoAndTwoFactor<TUser>(group, confirmEmailEndpointName, mapMethod);
        return new CompositeEndpointConventionBuilder(confirm, group);
    }
}
