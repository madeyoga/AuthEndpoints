using System.Buffers.Text;
using System.Security.Claims;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.SignIn;

internal sealed class CookieSignInCompleter<TUser> : ISignInCompleter<TUser>
    where TUser : class
{
    private readonly SignInManager<TUser> _signInManager;

    public CookieSignInCompleter(SignInManager<TUser> signInManager)
    {
        _signInManager = signInManager;
    }

    public async Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        SignInCompletionContext context,
        CancellationToken cancellationToken = default)
    {
        if (!await SignInCompletionResults.AllowedAsync(_signInManager, user))
        {
            return SignInCompletionResults.Denied(context, includePasskeyCredentialId: true);
        }

        // LoginCookie: persistent only when useSessionCookies=false. useCookies is ignored.
        var isPersistent = context.UseSessionCookies == false;
        _signInManager.AuthenticationScheme = IdentityConstants.ApplicationScheme;
        if (context.RememberTwoFactorClient)
        {
            await _signInManager.RememberTwoFactorClientAsync(user);
        }

        await SignInAsync(user, context, isPersistent);

        if (context.Method == SignInMethod.External)
        {
            await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            return Results.Redirect(string.IsNullOrEmpty(context.ReturnUrl) ? "/" : context.ReturnUrl);
        }

        if (context.Method == SignInMethod.Passkey
            && context.PasskeyKind == PasskeySignInKind.Register
            && context.PasskeyCredentialId is { Length: > 0 })
        {
            return TypedResults.Ok(new PasskeyCredentialResponse(
                Base64Url.EncodeToString(context.PasskeyCredentialId)));
        }

        return TypedResults.Empty;
    }

    private Task SignInAsync(TUser user, SignInCompletionContext context, bool isPersistent)
    {
        if (context.Method == SignInMethod.Password)
        {
            var amr = context.UsedTwoFactor ? "mfa" : "pwd";
            return _signInManager.SignInWithClaimsAsync(user, isPersistent, [new Claim("amr", amr)]);
        }

        return _signInManager.SignInAsync(user, isPersistent);
    }
}

internal sealed class IdentityBearerSignInCompleter<TUser> : ISignInCompleter<TUser>
    where TUser : class
{
    private readonly SignInManager<TUser> _signInManager;

    public IdentityBearerSignInCompleter(SignInManager<TUser> signInManager)
    {
        _signInManager = signInManager;
    }

    public async Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        SignInCompletionContext context,
        CancellationToken cancellationToken = default)
    {
        if (!await SignInCompletionResults.AllowedAsync(_signInManager, user))
        {
            return SignInCompletionResults.Denied(context, includePasskeyCredentialId: true);
        }

        var isPersistent = SignInScheme.Configure(
            _signInManager,
            context.UseCookies,
            context.UseSessionCookies);

        if (context.RememberTwoFactorClient
            && _signInManager.AuthenticationScheme == IdentityConstants.ApplicationScheme)
        {
            await _signInManager.RememberTwoFactorClientAsync(user);
        }

        await SignInAsync(user, context, isPersistent);

        // Cookie sign-in only sets the application cookie, so passkey register can still write credentialId.
        // Bearer sign-in writes AccessTokenResponse inside SignInAsync. A second body throws
        // "response has already started", so register returns that token response alone.
        if (context.Method == SignInMethod.Passkey
            && context.PasskeyKind == PasskeySignInKind.Register
            && context.PasskeyCredentialId is { Length: > 0 }
            && _signInManager.AuthenticationScheme == IdentityConstants.ApplicationScheme)
        {
            return TypedResults.Ok(new PasskeyCredentialResponse(
                Base64Url.EncodeToString(context.PasskeyCredentialId)));
        }

        return TypedResults.Empty;
    }

    private Task SignInAsync(TUser user, SignInCompletionContext context, bool isPersistent)
    {
        if (context.Method == SignInMethod.Password)
        {
            var amr = context.UsedTwoFactor ? "mfa" : "pwd";
            return _signInManager.SignInWithClaimsAsync(user, isPersistent, [new Claim("amr", amr)]);
        }

        return _signInManager.SignInAsync(user, isPersistent);
    }
}

internal sealed class JwtSignInCompleter<TUser> : ISignInCompleter<TUser>
    where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly SignInManager<TUser> _signInManager;
    private readonly IUserClaimsPrincipalFactory<TUser> _claimsFactory;
    private readonly IAccessTokenGenerator _accessTokenGenerator;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly RefreshTokenCookieWriter _refreshTokenCookieWriter;

    public JwtSignInCompleter(
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,
        IAccessTokenGenerator accessTokenGenerator,
        IRefreshTokenService refreshTokenService,
        RefreshTokenCookieWriter refreshTokenCookieWriter)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _claimsFactory = claimsFactory;
        _accessTokenGenerator = accessTokenGenerator;
        _refreshTokenService = refreshTokenService;
        _refreshTokenCookieWriter = refreshTokenCookieWriter;
    }

    public async Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        SignInCompletionContext context,
        CancellationToken cancellationToken = default)
    {
        if (!await SignInCompletionResults.AllowedAsync(_signInManager, user))
        {
            // Jwt passkey register denial is an empty 200, matching JwtPasskeySignInCompleter.
            return SignInCompletionResults.Denied(context, includePasskeyCredentialId: false);
        }

        var claimsPrincipal = await _claimsFactory.CreateAsync(user);
        var userId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("User principal is missing NameIdentifier.");
        var securityStamp = await _userManager.GetSecurityStampAsync(user);
        var refreshToken = await _refreshTokenService.CreateAsync(userId, securityStamp);
        _refreshTokenCookieWriter.Write(httpContext, refreshToken);

        if (context.Method == SignInMethod.External)
        {
            await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            return Results.Redirect(string.IsNullOrEmpty(context.ReturnUrl) ? "/" : context.ReturnUrl);
        }

        var response = new SimpleJwtTokenResponse
        {
            AccessToken = _accessTokenGenerator.GenerateAccessToken(claimsPrincipal),
            TokenType = "Bearer",
        };

        // Same body as JWT /create. Passkey register does not add credentialId.
        return Results.Ok(response);
    }
}

internal static class SignInCompletionResults
{
    public static async Task<bool> AllowedAsync<TUser>(SignInManager<TUser> signInManager, TUser user)
        where TUser : class
    {
        return !await signInManager.UserManager.IsLockedOutAsync(user)
            && await signInManager.CanSignInAsync(user);
    }

    public static IResult Denied(SignInCompletionContext context, bool includePasskeyCredentialId)
    {
        if (context.Method == SignInMethod.Passkey && context.PasskeyKind == PasskeySignInKind.Register)
        {
            if (includePasskeyCredentialId && context.PasskeyCredentialId is { Length: > 0 })
            {
                return TypedResults.Ok(new PasskeyCredentialResponse(
                    Base64Url.EncodeToString(context.PasskeyCredentialId)));
            }

            return TypedResults.Ok();
        }

        return TypedResults.Problem(
            title: "Unauthorized",
            detail: "Invalid credentials.",
            statusCode: StatusCodes.Status401Unauthorized);
    }
}
