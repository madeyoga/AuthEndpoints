namespace AuthEndpoints.OpenIddict;

/// <summary>
/// The longest values the OAuth server writes to its own rows. The server refuses longer input before it reaches a store,
/// so a store's columns must hold at least these. The EF Core model uses them.
/// </summary>
public static class OAuthStoreLimits
{
    /// <summary>A client id, long enough for a client ID metadata document URL. OpenIddict's own model allows 100.</summary>
    public const int ClientIdLength = 255;

    /// <summary>An OpenID Connect <c>nonce</c> on a pending consent request.</summary>
    public const int NonceLength = 512;

    /// <summary>The joined authentication methods (<c>amr</c>) on a pending consent request.</summary>
    public const int AuthenticationMethodsLength = 128;

    /// <summary>A developer app's name.</summary>
    public const int DeveloperAppNameLength = 200;

    /// <summary>A developer app's description.</summary>
    public const int DeveloperAppDescriptionLength = 1000;
}
