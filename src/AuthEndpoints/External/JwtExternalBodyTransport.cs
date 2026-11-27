namespace AuthEndpoints.External.OAuth;

internal static class JwtExternalBodyTransport
{
    public const string Message =
        "External sign-in cannot finish a JWT session when SimpleJwtOptions.RefreshTokenTransport is Body. " +
        "External sign-in redirects and cannot deliver the refresh token. Use RefreshTokenTransport.Cookie.";
}
