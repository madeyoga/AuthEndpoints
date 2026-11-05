using System.Security.Claims;
using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthEndpoints.OpenIddict;

internal sealed record IssuedAuthorizationCode(string Code, string AuthorizationId);

/// <summary>
/// Mints an authorization-code reference token from a principal the host already built.
/// The authorize request and the consent approval are different HTTP requests, so this goes through the
/// OpenIddict dispatcher instead of the authorization-endpoint sign-in.
/// </summary>
internal static class OAuthCodeIssuer
{
    public static async Task<IssuedAuthorizationCode> IssueAsync(
        IOpenIddictServerDispatcher dispatcher,
        OpenIddictServerOptions options,
        Uri issuer,
        string clientId,
        string redirectUri,
        string codeChallenge,
        string scope,
        string resource,
        string? nonce,
        ClaimsPrincipal principal,
        CancellationToken cancellationToken)
    {
        principal.SetScopes(scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        principal.SetResources(resource);

        var request = new OpenIddictRequest
        {
            ClientId = clientId,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = OpenIddictConstants.CodeChallengeMethods.Sha256,
            ResponseType = OpenIddictConstants.ResponseTypes.Code,
            Scope = scope,
            // OpenIddict copies it from the code into the ID token.
            Nonce = nonce,
        };
        request.SetParameter(OpenIddictConstants.Parameters.Resource, resource);

        var transaction = new OpenIddictServerTransaction
        {
            EndpointType = OpenIddictServerEndpointType.Authorization,
            BaseUri = issuer,
            Request = request,
            Options = options,
            CancellationToken = cancellationToken,
            Logger = NullLogger.Instance,
            Response = new OpenIddictResponse(),
        };
        transaction.SetProperty(
            typeof(OpenIddictServerEvents.ProcessAuthenticationContext).FullName!,
            new OpenIddictServerEvents.ProcessAuthenticationContext(transaction));
        var context = new OpenIddictServerEvents.ProcessSignInContext(transaction)
        {
            Principal = principal,
        };
        await dispatcher.DispatchAsync(context);
        if (context.IsRejected || string.IsNullOrEmpty(context.AuthorizationCode))
        {
            throw new InvalidOperationException(
                context.ErrorDescription ?? context.Error ?? "The authorization code was not issued.");
        }

        var authorizationId = principal.GetAuthorizationId()
            ?? throw new InvalidOperationException("The authorization was not stored.");
        return new IssuedAuthorizationCode(context.AuthorizationCode, authorizationId);
    }
}
