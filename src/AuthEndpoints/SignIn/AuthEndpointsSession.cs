namespace AuthEndpoints;

/// <summary>
/// Built-in sign-in session. Selects the keyed <see cref="ISignInCompleter{TUser}"/> of the same name.
/// </summary>
public enum AuthEndpointsSession
{
    /// <summary>
    /// Application cookie (<see cref="SignInCompleters.Cookie"/>).
    /// </summary>
    Cookie = 0,

    /// <summary>
    /// Identity bearer token, or an application cookie when <c>useCookies</c> or <c>useSessionCookies</c> is set
    /// (<see cref="SignInCompleters.IdentityBearer"/>).
    /// </summary>
    IdentityBearer = 1,

    /// <summary>
    /// Simple JWT access token and HttpOnly refresh cookie (<see cref="SignInCompleters.Jwt"/>).
    /// Requires <c>AddJwtEndpoints</c>.
    /// </summary>
    Jwt = 2,
}
