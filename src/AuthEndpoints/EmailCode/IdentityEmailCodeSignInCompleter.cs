using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.EmailCode;

/// <summary>
/// Completes email-code sign-in with an Identity application cookie or bearer token.
/// <c>useCookies</c> gives a persistent cookie, <c>useSessionCookies</c> gives a session cookie,
/// and neither gives an Identity bearer token.
/// </summary>
public sealed class IdentityEmailCodeSignInCompleter<TUser> : IEmailCodeSignInCompleter<TUser>
    where TUser : class
{
    private readonly SignInManager<TUser> _signInManager;

    public IdentityEmailCodeSignInCompleter(SignInManager<TUser> signInManager)
    {
        _signInManager = signInManager;
    }

    public async Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        EmailCodeSignInContext context,
        CancellationToken cancellationToken = default)
    {
        var isPersistent = SignInScheme.Configure(
            _signInManager,
            context.UseCookies,
            context.UseSessionCookies);

        await _signInManager.SignInAsync(user, isPersistent);
        return TypedResults.Empty;
    }
}
