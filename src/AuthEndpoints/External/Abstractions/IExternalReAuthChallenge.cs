using Microsoft.AspNetCore.Authentication;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Optional. Implement on an <see cref="IExternalAuthProvider"/> to ask the provider for a fresh sign-in
/// during step-up. OpenID Connect schemes get <c>prompt=login</c> and <c>max_age=0</c> without this.
/// </summary>
public interface IExternalReAuthChallenge
{
    /// <summary>Adds provider-specific parameters that request a fresh sign-in.</summary>
    void ConfigureFreshSignIn(AuthenticationProperties properties);
}
