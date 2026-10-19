using AspNet.Security.OAuth.GitHub;
using AuthEndpoints.External.OAuth;

namespace AuthEndpoints.OAuth.GitHub;

public sealed class GitHubExternalAuthProvider : IExternalAuthProvider
{
    public string Scheme => GitHubAuthenticationDefaults.AuthenticationScheme;

    public string LoginPath => "login/github";

    public string CallbackPath => "login/github/callback";

    public string CallbackEndpointName => "GitHubLoginCallback";
}
