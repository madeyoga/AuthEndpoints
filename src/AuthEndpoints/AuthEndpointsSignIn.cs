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
    /// Used by <c>AddAuthEndpointsBearer</c> / <c>MapAuthEndpointsBearer</c>.
    /// </summary>
    IdentityBearer = 1,
}
