using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.EmailCode;

[Obsolete(LegacyCompleterMessages.Obsolete)]
public sealed class EmailCodeSignInContext
{
    public bool? UseCookies { get; init; }

    public bool? UseSessionCookies { get; init; }

    public bool IsNewUser { get; init; }
}

/// <summary>
/// Finishes email-code sign-in after the endpoint has checked lockout, two-factor, and <c>CanSignInAsync</c>.
/// </summary>
[Obsolete(LegacyCompleterMessages.Obsolete)]
public interface IEmailCodeSignInCompleter<TUser>
    where TUser : class
{
    Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        EmailCodeSignInContext context,
        CancellationToken cancellationToken = default);
}
