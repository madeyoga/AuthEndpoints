using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Identity;

/// <summary>Where <c>AddAnyCallerScheme</c> sends each kind of credential.</summary>
public sealed class AnyCallerSchemeOptions
{
    /// <summary>For requests without an <c>Authorization</c> header. Default: the Identity application cookie.</summary>
    public string CookieScheme { get; set; } = IdentityConstants.ApplicationScheme;

    /// <summary>
    /// For every other request with an <c>Authorization</c> header, such as <c>Bearer</c> tokens. Default
    /// <see langword="null"/>: the JWT bearer scheme when it is registered, else Identity bearer. Set it to the OAuth
    /// validation scheme (<c>OAuthServerServiceCollectionExtensions.ValidationScheme</c>) when assistants call with OAuth
    /// access tokens.
    /// </summary>
    public string? BearerScheme { get; set; }

    /// <summary>For API keys, recognized by <see cref="ApiKeyPrefix"/>. Optional; set both or neither.</summary>
    public string? ApiKeyScheme { get; set; }

    /// <summary>
    /// The start of every API key, such as <c>ak_</c>. A request whose <c>Authorization</c> credential (the part after
    /// the first space, as in <c>Bearer ak_…</c>) starts with it goes to <see cref="ApiKeyScheme"/>. Compared ordinally.
    /// </summary>
    public string? ApiKeyPrefix { get; set; }
}

public static class AnyCallerAuthenticationBuilderExtensions
{
    /// <summary>The scheme name <see cref="AddAnyCallerScheme"/> registers by default: <c>AuthEndpoints.AnyCaller</c>.</summary>
    public const string SchemeName = "AuthEndpoints.AnyCaller";

    /// <summary>
    /// Adds an opt-in policy scheme that picks exactly one handler from the request's credential: an API key (by
    /// <see cref="AnyCallerSchemeOptions.ApiKeyPrefix"/>) goes to the API key scheme, any other <c>Authorization</c>
    /// header to the bearer scheme, and a request without one to the application cookie. A request with a bad token is
    /// never signed in by a cookie it also sends: it gets <c>401</c>. It does not change the default scheme. Use it in
    /// a policy (<c>AddAuthenticationSchemes(AnyCallerAuthenticationBuilderExtensions.SchemeName)</c>), or make it the
    /// default yourself. Pair a route with <c>RequireDirectPerson()</c> to refuse delegated tokens and API keys.
    /// </summary>
    public static AuthenticationBuilder AddAnyCallerScheme(
        this AuthenticationBuilder builder,
        Action<AnyCallerSchemeOptions>? configure = null,
        string scheme = SchemeName)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        var settings = new AnyCallerSchemeOptions();
        configure?.Invoke(settings);
        if (string.IsNullOrWhiteSpace(settings.CookieScheme))
        {
            throw new ArgumentException("AnyCallerSchemeOptions.CookieScheme is required.", nameof(configure));
        }

        if (string.IsNullOrEmpty(settings.ApiKeyScheme) != string.IsNullOrEmpty(settings.ApiKeyPrefix))
        {
            throw new ArgumentException("Set both AnyCallerSchemeOptions.ApiKeyScheme and ApiKeyPrefix, or neither.", nameof(configure));
        }

        var selector = new AnyCallerSelector(settings);
        return builder.AddPolicyScheme(scheme, "Any AuthEndpoints caller", options => options.ForwardDefaultSelector = selector.Select);
    }
}

internal sealed class AnyCallerSelector(AnyCallerSchemeOptions settings)
{
    private string? _bearer = settings.BearerScheme;

    public string Select(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(header))
        {
            return settings.CookieScheme;
        }

        if (settings.ApiKeyPrefix is { Length: > 0 } prefix && settings.ApiKeyScheme is { } apiKeyScheme)
        {
            var space = header.IndexOf(' ', StringComparison.Ordinal);
            var credential = (space < 0 ? header : header[(space + 1)..]).TrimStart();
            if (credential.StartsWith(prefix, StringComparison.Ordinal))
            {
                return apiKeyScheme;
            }
        }

        return _bearer ??= DefaultBearer(context.RequestServices);
    }

    private static string DefaultBearer(IServiceProvider services)
    {
        var schemes = services.GetService<IOptions<AuthenticationOptions>>()?.Value.SchemeMap;
        return schemes?.ContainsKey(JwtBearerDefaults.AuthenticationScheme) == true
            ? JwtBearerDefaults.AuthenticationScheme
            : IdentityConstants.BearerScheme;
    }
}
