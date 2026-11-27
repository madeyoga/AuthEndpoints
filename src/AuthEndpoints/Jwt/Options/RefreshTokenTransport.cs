namespace AuthEndpoints.Jwt;

/// <summary>
/// How the JWT session carries its refresh token. Set it with <see cref="SimpleJwtOptions.RefreshTokenTransport"/>.
/// </summary>
public enum RefreshTokenTransport
{
    /// <summary>
    /// HttpOnly cookie <c>AuthEndpoints.Jwt.RefreshToken</c>. Refresh and logout require antiforgery.
    /// </summary>
    Cookie = 0,

    /// <summary>
    /// JSON <c>refreshToken</c> on login, email-code verify, passkey sign-in, and refresh.
    /// Refresh and logout read that value from the body. No antiforgery and no <c>csrfToken</c> route.
    /// </summary>
    Body = 1,
}
