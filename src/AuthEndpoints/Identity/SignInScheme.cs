using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Identity;

internal static class SignInScheme
{
    public static bool Configure<TUser>(
        SignInManager<TUser> signInManager,
        bool? useCookies,
        bool? useSessionCookies)
        where TUser : class
    {
        var useCookieScheme = useCookies == true || useSessionCookies == true;
        var isPersistent = useCookies == true && useSessionCookies != true;
        signInManager.AuthenticationScheme = useCookieScheme
            ? IdentityConstants.ApplicationScheme
            : IdentityConstants.BearerScheme;
        return isPersistent;
    }
}
