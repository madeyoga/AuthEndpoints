using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
using OpenIddict.Validation.AspNetCore;

namespace AuthEndpoints.OpenIddict;

/// <summary>
/// Reads the access token from the <c>access_token</c> query parameter, but only on the path prefixes listed in
/// <see cref="OAuthServerOptions.QueryStringTokenPaths"/>. OpenIddict's own query string and form body extraction
/// is turned off, so every other route accepts only <c>Authorization: Bearer</c>.
/// </summary>
internal sealed class ExtractAccessTokenFromAllowedQueryPaths(IOptions<OAuthServerOptions> options)
    : IOpenIddictValidationHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>
{
    private readonly PathString[] _paths = options.Value.QueryStringTokenPaths.Select(path => new PathString(path)).ToArray();

    public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
        = OpenIddictValidationHandlerDescriptor.CreateBuilder<OpenIddictValidationEvents.ProcessAuthenticationContext>()
            .AddFilter<OpenIddictValidationAspNetCoreHandlerFilters.RequireHttpRequest>()
            .UseSingletonHandler<ExtractAccessTokenFromAllowedQueryPaths>()
            // Where the built-in query string handler sits: after the Authorization header, before validation.
            .SetOrder(OpenIddictValidationAspNetCoreHandlers.ExtractAccessTokenFromQueryString.Descriptor.Order)
            .SetType(OpenIddictValidationHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(OpenIddictValidationEvents.ProcessAuthenticationContext context)
    {
        // A token from the Authorization header wins.
        if (_paths.Length == 0 || !context.ExtractAccessToken || !string.IsNullOrEmpty(context.AccessToken))
        {
            return ValueTask.CompletedTask;
        }

        var request = context.Transaction.GetHttpRequest();
        // Request.Path is relative to PathBase, so the prefixes are too.
        if (request is null || !_paths.Any(path => request.Path.StartsWithSegments(path)))
        {
            return ValueTask.CompletedTask;
        }

        string? token = request.Query[OpenIddictConstants.Parameters.AccessToken];
        if (!string.IsNullOrEmpty(token))
        {
            context.AccessToken = token;
        }

        return ValueTask.CompletedTask;
    }
}
