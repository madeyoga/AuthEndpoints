using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Core;

/// <summary>
/// AuthenticationService that skips missing Bearer or TokenBearer handler
/// </summary>
internal class CustomAuthenticationService : AuthenticationService
{
    private HashSet<ClaimsPrincipal>? _transformCache;

    public CustomAuthenticationService(IAuthenticationSchemeProvider schemes,
                                       IAuthenticationHandlerProvider handlers,
                                       IClaimsTransformation transform,
                                       IOptions<AuthenticationOptions> options) : base(schemes, handlers, transform, options)
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
            if (scheme == "Bearer" || scheme == "TokenBearer")
            {
                // return NoResult instead of throwing an error.
                // This will continue the foreach (var scheme in policy.AuthenticationSchemes) loop
                // in PolicyEvaluator.AuthenticateAsync
                return AuthenticateResult.NoResult();
            }
            throw await CreateMissingHandlerException(scheme);
        }

        // Handlers should not return null, but we'll be tolerant of null values for legacy reasons.
        var result = (await handler.AuthenticateAsync()) ?? AuthenticateResult.NoResult();
        Console.WriteLine($"{result.Succeeded} {scheme}");
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

    public override async Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
    {
        if (scheme == null)
        {
            var defaultChallengeScheme = await Schemes.GetDefaultChallengeSchemeAsync();
            scheme = defaultChallengeScheme?.Name;
            if (scheme == null)
            {
                throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultChallengeScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
            }
        }

        var handler = await Handlers.GetHandlerAsync(context, scheme);
        if (handler == null)
        {
            if (scheme == "Bearer" || scheme == "TokenBearer")
            {
                return;
            }
            throw await CreateMissingHandlerException(scheme);
        }

        await handler.ChallengeAsync(properties);
    }

    public override async Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
    {
        if (scheme == null)
        {
            var defaultForbidScheme = await Schemes.GetDefaultForbidSchemeAsync();
            scheme = defaultForbidScheme?.Name;
            if (scheme == null)
            {
                throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultForbidScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
            }
        }

        var handler = await Handlers.GetHandlerAsync(context, scheme);
        if (handler == null)
        {
            if (scheme == "Bearer" || scheme == "TokenBearer")
            {
                return;
            }
            throw await CreateMissingHandlerException(scheme);
        }

        await handler.ForbidAsync(properties);
    }

    private async Task<Exception> CreateMissingHandlerException(string scheme)
    {
        var schemes = string.Join(", ", (await Schemes.GetAllSchemesAsync()).Select(sch => sch.Name));

        var footer = $" Did you forget to call AddAuthentication().Add[SomeAuthHandler](\"{scheme}\",...)?";

        if (string.IsNullOrEmpty(schemes))
        {
            return new InvalidOperationException(
                $"No authentication handlers are registered." + footer);
        }

        return new InvalidOperationException(
            $"No authentication handler is registered for the scheme '{scheme}'. The registered schemes are: {schemes}." + footer);
    }
}
