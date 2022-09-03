using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Core;

/// <summary>
/// AuthenticationService that skips missing authentication handler
/// </summary>
internal class SkipMissingHandlerAuthenticationService : AuthenticationService
{
    private HashSet<ClaimsPrincipal>? _transformCache;

    public SkipMissingHandlerAuthenticationService(IAuthenticationSchemeProvider schemes, IAuthenticationHandlerProvider handlers, IClaimsTransformation transform, IOptions<AuthenticationOptions> options) : base(schemes, handlers, transform, options)
    {
    }

    /// <summary>
    /// Authenticate for the specified authentication scheme.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/>.</param>
    /// <param name="scheme">The name of the authentication scheme.</param>
    /// <returns>The result.</returns>
    public override async Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
    {
        if (scheme == null)
        {
            var defaultScheme = await Schemes.GetDefaultAuthenticateSchemeAsync();
            scheme = defaultScheme?.Name;
            if (scheme == null)
            {
                throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultAuthenticateScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
            }
        }

        var handler = await Handlers.GetHandlerAsync(context, scheme);
        if (handler == null)
        {
            // return NoResult instead of throwing an error.
            // This will continue the foreach (var scheme in policy.AuthenticationSchemes) loop
            // in PolicyEvaluator.AuthenticateAsync
            return AuthenticateResult.NoResult();
        }

        // Handlers should not return null, but we'll be tolerant of null values for legacy reasons.
        var result = (await handler.AuthenticateAsync()) ?? AuthenticateResult.NoResult();

        if (result.Succeeded)
        {
            var principal = result.Principal!;
            var doTransform = true;
            _transformCache ??= new HashSet<ClaimsPrincipal>();
            if (_transformCache.Contains(principal))
            {
                doTransform = false;
            }

            if (doTransform)
            {
                principal = await Transform.TransformAsync(principal);
                _transformCache.Add(principal);
            }
            return AuthenticateResult.Success(new AuthenticationTicket(principal, result.Properties, result.Ticket!.AuthenticationScheme));
        }
        return result;
    }
}
