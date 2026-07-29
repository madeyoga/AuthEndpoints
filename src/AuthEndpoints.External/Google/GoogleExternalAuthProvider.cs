using Microsoft.AspNetCore.Authentication.Google;

namespace AuthEndpoints.External.Google;

/// <summary>
/// Google provider route metadata for external auth endpoints.
/// </summary>
public sealed class GoogleExternalAuthProvider : IExternalAuthProvider
{
    public string Scheme => GoogleDefaults.AuthenticationScheme;

    public string LoginPath => "login/google";

    public string CallbackPath => "login/google/callback";

    public string CallbackEndpointName => "GoogleLoginCallback";
}
