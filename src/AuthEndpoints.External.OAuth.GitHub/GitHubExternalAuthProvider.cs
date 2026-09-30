using AspNet.Security.OAuth.GitHub;

namespace AuthEndpoints.External.OAuth.GitHub;

/// <summary>
/// GitHub provider route metadata for external auth endpoints.
/// </summary>
public sealed class GitHubExternalAuthProvider : IExternalAuthProvider
{
    public string Scheme => GitHubAuthenticationDefaults.AuthenticationScheme;

    public string LoginPath => "login/github";

    public string CallbackPath => "login/github/callback";

    public string CallbackEndpointName => "GitHubLoginCallback";
}
