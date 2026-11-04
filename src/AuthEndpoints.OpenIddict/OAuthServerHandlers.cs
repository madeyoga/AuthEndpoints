using Microsoft.AspNetCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// The consent endpoint issues codes through the dispatcher, outside an HTTP request,
/// so there is no response to write. Mark the request handled instead.
/// </summary>
internal sealed class SkipDetachedAuthorizationResponse
    : IOpenIddictServerHandler<OpenIddictServerEvents.ApplyAuthorizationResponseContext>
{
    public ValueTask HandleAsync(OpenIddictServerEvents.ApplyAuthorizationResponseContext context)
    {
        if (context.Transaction.GetHttpRequest() is null)
        {
            context.HandleRequest();
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Fixes RFC 8414 metadata. OpenIddict builds endpoint URLs from the request host even when an issuer is set,
/// so a spoofed <c>Host</c> header would show up in the document. Rebase them onto the issuer, add the
/// registration endpoint when dynamic registration is on, and advertise <c>none</c> for public clients.
/// </summary>
internal sealed class AttachRegistrationMetadata(IOptions<OAuthServerOptions> options)
    : IOpenIddictServerHandler<OpenIddictServerEvents.HandleConfigurationRequestContext>
{
    public ValueTask HandleAsync(OpenIddictServerEvents.HandleConfigurationRequestContext context)
    {
        var settings = options.Value;
        if (settings.Issuer is not { } issuer)
        {
            return ValueTask.CompletedTask;
        }

        var authority = issuer.GetLeftPart(UriPartial.Authority);
        context.AuthorizationEndpoint = Rebase(context.AuthorizationEndpoint, authority);
        context.TokenEndpoint = Rebase(context.TokenEndpoint, authority);
        context.RevocationEndpoint = Rebase(context.RevocationEndpoint, authority);
        context.IntrospectionEndpoint = Rebase(context.IntrospectionEndpoint, authority);
        context.JsonWebKeySetEndpoint = Rebase(context.JsonWebKeySetEndpoint, authority);
        context.UserInfoEndpoint = Rebase(context.UserInfoEndpoint, authority);
        context.EndSessionEndpoint = Rebase(context.EndSessionEndpoint, authority);
        context.DeviceAuthorizationEndpoint = Rebase(context.DeviceAuthorizationEndpoint, authority);
        context.PushedAuthorizationEndpoint = Rebase(context.PushedAuthorizationEndpoint, authority);

        if (settings.DynamicRegistration.Enabled)
        {
            var pathBase = context.Transaction.GetHttpRequest()?.PathBase.Value ?? string.Empty;
            context.Metadata["registration_endpoint"] = authority + pathBase + OAuthServerConstants.RegistrationEndpointPath;
        }

        // Public clients authenticate with PKCE alone.
        context.TokenEndpointAuthenticationMethods.Add(OpenIddictConstants.ClientAuthenticationMethods.None);
        context.RevocationEndpointAuthenticationMethods.Add(OpenIddictConstants.ClientAuthenticationMethods.None);
        return ValueTask.CompletedTask;
    }

    private static Uri? Rebase(Uri? endpoint, string authority)
        => endpoint is null ? null : new Uri(authority + endpoint.PathAndQuery);
}
