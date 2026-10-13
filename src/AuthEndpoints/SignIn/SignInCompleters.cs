namespace AuthEndpoints;

/// <summary>
/// Keyed-service names for the built-in <see cref="ISignInCompleter{TUser}"/> implementations.
/// </summary>
public static class SignInCompleters
{
    /// <summary>
    /// Application-cookie session. Registered by <c>AddAuthEndpointsIdentity</c>.
    /// </summary>
    public const string Cookie = "Cookie";

    /// <summary>
    /// Identity bearer token, or an application cookie when the cookie query flags are set.
    /// Registered by <c>AddAuthEndpointsIdentity</c>.
    /// </summary>
    public const string IdentityBearer = "IdentityBearer";

    /// <summary>
    /// Simple JWT access token and HttpOnly refresh cookie. Registered by <c>AddJwtEndpoints</c>.
    /// </summary>
    public const string Jwt = "Jwt";
}
