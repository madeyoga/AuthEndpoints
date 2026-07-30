using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Completes sign-in after an external login has been resolved to a local user.
/// Default implementation issues an Identity application cookie; replace for JWT or other modes.
/// </summary>
public interface IExternalLoginCompleter<TUser>
    where TUser : class
{
    Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        ExternalLoginInfo info,
        string? returnUrl,
        CancellationToken cancellationToken = default);
}
