using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// Refuses, with <c>403</c>, a caller that is known not to be a person calling directly: an OAuth access token (a client
/// acting for the person) or an API key. The consent, connected apps, and developer app routes are for the person only.
/// They authenticate with <see cref="OAuthServerOptions.AuthenticationScheme"/>, which a host may point at its own
/// cookie, so an identity without a caller kind is let through here; a host scheme that forwards tokens is refused.
/// </summary>
internal static class OAuthPersonOnly
{
    public static TBuilder RefuseDelegatedCallers<TBuilder>(this TBuilder builder, string detail)
        where TBuilder : IEndpointConventionBuilder
        => builder.AddEndpointFilter(async (context, next) => Refused(context.HttpContext)
            ? Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: "Forbidden", detail: detail)
            : await next(context));

    public static bool Refused(HttpContext http)
        => http.User.IsOAuthDelegated()
            || http.User.GetCallerKind() is CallerKinds.Delegated or CallerKinds.ApiKey;
}
