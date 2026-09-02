namespace AuthEndpoints;

/// <summary>
/// Which Identity sign-in module the opinionated facade maps under
/// <see cref="AuthEndpointsOptions.IdentityPath"/>.
/// </summary>
public enum AuthEndpointsSignIn
{
    /// <summary>
    /// Cookie sessions via <c>MapCookieAuthEndpoints</c> (<c>LoginCookie</c>).
    /// Default for <c>AddAuthEndpoints</c> / <c>MapAuthEndpoints</c>.
    /// </summary>
    Cookie = 0,

    /// <summary>
    /// Identity bearer tokens via <c>MapBearerAuthEndpoints</c> (<c>Login</c>).
    /// Set <see cref="AuthEndpointsOptions.SignIn"/> or pass this value to <c>AddAuthEndpoints</c>.
    /// </summary>
    IdentityBearer = 1,
}
