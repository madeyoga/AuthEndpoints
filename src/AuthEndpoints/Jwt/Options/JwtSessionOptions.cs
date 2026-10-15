namespace AuthEndpoints.Jwt;

/// <summary>
/// How the JWT session carries its refresh token.
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

/// <summary>
/// JWT session refresh behavior. Configure with <c>Configure&lt;JwtSessionOptions&gt;</c>.
/// The default is the cookie transport.
/// </summary>
public class JwtSessionOptions
{
    /// <summary>
    /// Where the refresh token is issued and accepted. Default: <see cref="RefreshTokenTransport.Cookie"/>.
    /// </summary>
    public RefreshTokenTransport RefreshTokenTransport { get; set; } = RefreshTokenTransport.Cookie;

    /// <summary>
    /// Lifetime of one refresh token from the moment it is issued.
    /// Default: 14 days. A successor expires at most this far ahead, and never later than
    /// <see cref="AbsoluteLifetime"/> from the original sign-in.
    /// </summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Lifetime of a refresh-token family, measured from the original sign-in.
    /// Rotation cannot extend it. Default: 14 days, the same window as <see cref="RefreshTokenLifetime"/>,
    /// so refreshing does not keep a session alive past that cap.
    /// </summary>
    public TimeSpan AbsoluteLifetime { get; set; } = TimeSpan.FromDays(14);
}
