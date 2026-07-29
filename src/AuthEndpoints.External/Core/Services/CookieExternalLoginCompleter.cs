using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External;

/// <summary>
/// Completes external login by signing into the Identity application cookie (or configured scheme).
/// </summary>
public sealed class CookieExternalLoginCompleter<TUser> : IExternalLoginCompleter<TUser>
    where TUser : class
{
    private readonly SignInManager<TUser> _signInManager;
    private readonly ExternalAuthOptions _options;

    public CookieExternalLoginCompleter(
        SignInManager<TUser> signInManager,
        IOptions<ExternalAuthOptions> options)
    {
        _signInManager = signInManager;
        _options = options.Value;
    }

    public async Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        ExternalLoginInfo info,
        string? returnUrl,
        CancellationToken cancellationToken = default)
    {
        if (!string.IsNullOrEmpty(_options.SignInScheme))
        {
            _signInManager.AuthenticationScheme = _options.SignInScheme;
        }

        await _signInManager.SignInAsync(user, isPersistent: _options.IsPersistent);

        var redirectUrl = ExternalAuthReturnUrl.Resolve(httpContext, returnUrl, _options.DefaultReturnUrl);
        return Results.Redirect(redirectUrl);
    }
}
