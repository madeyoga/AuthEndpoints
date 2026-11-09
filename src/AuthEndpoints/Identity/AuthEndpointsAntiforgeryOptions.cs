using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Identity;

/// <summary>
/// Options for the <c>RequireAntiforgery()</c> endpoint filter and for the ReAuth cookie decision
/// on <c>POST /confirmIdentity</c>.
/// </summary>
/// <remarks>
/// Configure with <c>services.Configure&lt;AuthEndpointsAntiforgeryOptions&gt;(o =&gt; o.BearerSchemes.Add("MyScheme"))</c>.
/// A package that registers its own header-based scheme can add it the same way from its
/// <c>AddXxx</c> method.
/// </remarks>
public sealed class AuthEndpointsAntiforgeryOptions
{
    /// <summary>
    /// Authentication schemes that let a request skip the CSRF check of <c>RequireAntiforgery()</c>.
    /// Default: <c>Identity.Bearer</c> (<see cref="IdentityConstants.BearerScheme"/>) and
    /// <c>Bearer</c> (<see cref="JwtBearerDefaults.AuthenticationScheme"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The check is skipped only when all of these are true: the Identity application cookie does not
    /// authenticate the request, the request has a non-empty <c>Authorization: Bearer</c> header, and one
    /// scheme in this list authenticates the request. A cross-site request cannot set the
    /// <c>Authorization</c> header without a CORS preflight, so the header is the CSRF signal.
    /// </para>
    /// <para>
    /// Add only schemes that read their credential from the <c>Authorization: Bearer</c> header.
    /// A scheme that reads a cookie, or a query string, is not safe here: the browser sends a cookie on a
    /// cross-site request. Schemes whose handler is a cookie handler are ignored, and a request that the
    /// application cookie authenticates always needs the token. A scheme that reads another header, such
    /// as an API key in <c>X-Api-Key</c>, does not skip the check unless the request also carries an
    /// <c>Authorization: Bearer</c> header.
    /// </para>
    /// <para>
    /// The same list decides whether <c>POST /confirmIdentity</c> sets the ReAuth cookie: a request that
    /// would skip the CSRF check gets only the <c>reauthToken</c>.
    /// </para>
    /// <para>
    /// A route mapped with <c>RequireAntiforgery(allowBearer: false)</c> ignores this list and always
    /// needs the token.
    /// </para>
    /// </remarks>
    public IList<string> BearerSchemes { get; } = new List<string>
    {
        IdentityConstants.BearerScheme,
        JwtBearerDefaults.AuthenticationScheme,
    };
}
