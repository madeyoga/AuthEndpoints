using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Identity;

public static class AccountManagementEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps signed-in account routes: <c>/manage/info</c>, <c>/manage/2fa</c>, <c>/manage/authMethods</c>,
    /// <c>POST</c> and <c>DELETE /manage/password</c>, and <c>/confirmIdentity</c>.
    /// <c>POST /manage/password</c> sets a password when the account has none. It returns 404 when password
    /// sign-in is not mapped, and 400 when a password already exists.
    /// <c>DELETE /manage/password</c> removes the password when the account keeps another sign-in method.
    /// <c>POST /confirmIdentity/emailCode/send</c> is mapped when
    /// <c>AddEmailCodeSendEndpoints</c> or <c>AddEmailCodeEndpoints</c> was called.
    /// <c>AddEmailCodeSignInEndpoints</c> alone leaves that route unmapped.
    /// <c>POST /confirmIdentity/passkeyOptions</c> is mapped when passkeys are registered: <c>AddPasskeyEndpoints</c>,
    /// <c>AddPasskeySignInEndpoints</c>, or <c>AddPasskeyManagementEndpoints</c>.
    /// <c>AddAuthEndpoints(...).AddPasskeys()</c> registers passkey sign-in and management.
    /// Also maps confirm-email when that name is not mapped yet.
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
            alwaysMapPasskeyOptions: false);
    }

    internal static IEndpointConventionBuilder MapAccountManagementEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName,
        bool alwaysMapPasskeyOptions)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var features = AuthEndpointsFeatures.For(endpoints);
        AuthEndpointsFeatures.Require(
            features.AccountManagement,
            "AddAccountManagementEndpoints",
            "MapAccountManagementEndpoints");

        confirmEmailEndpointName ??= AuthEndpointsEndpointNames.ConfirmEmail<TUser>();
        var confirm = endpoints.MapConfirmEmailEndpoints<TUser>(confirmEmailEndpointName);

        var group = endpoints.MapGroup("");
        const string mapMethod = nameof(MapAccountManagementEndpoints);
        IdentityEndpointRoutes.MapConfirmIdentity<TUser>(group, requireAntiforgery: true, mapMethod);
        IdentityEndpointRoutes.MapEmailCodeReAuthSend<TUser>(group, requireAntiforgery: true, mapMethod);

        if (alwaysMapPasskeyOptions || features.Passkeys.CanConfirmIdentity)
        {
            IdentityEndpointRoutes.MapPasskeyOptions<TUser>(group, requireAntiforgery: true, mapMethod);
        }
        else
        {
            SkippedRoutes.Log(endpoints, SkippedRoutes.PasskeyConfirmIdentity);
        }

        IdentityEndpointRoutes.MapAuthMethods<TUser>(group, mapMethod);
        IdentityEndpointRoutes.MapManageInfoAndTwoFactor<TUser>(group, confirmEmailEndpointName, mapMethod);
        IdentityEndpointRoutes.MapSetPassword<TUser>(group, mapMethod);

        return new CompositeEndpointConventionBuilder(confirm, group);
    }
}
