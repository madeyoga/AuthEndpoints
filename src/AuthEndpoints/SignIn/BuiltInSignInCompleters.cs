using System.Buffers.Text;
using System.Security.Claims;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

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

        if (context.Method == SignInMethod.External)
        {
            return await CompleteExternalAsync(httpContext, user, context);
        }

        // LoginCookie: persistent only when useSessionCookies=false. useCookies is ignored.
        var isPersistent = context.UseSessionCookies == false;
        _signInManager.AuthenticationScheme = IdentityConstants.ApplicationScheme;
        if (context.RememberTwoFactorClient)
        {
            await _signInManager.RememberTwoFactorClientAsync(user);
        }

        await SignInAsync(user, context, isPersistent);

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

    private async Task<IResult> CompleteExternalAsync(HttpContext httpContext, TUser user, SignInCompletionContext context)
    {
        var options = httpContext.RequestServices.GetService<IOptions<ExternalAuthOptions>>()?.Value;
        if (options is null)
        {
            _signInManager.AuthenticationScheme = IdentityConstants.ApplicationScheme;
            await _signInManager.SignInAsync(user, isPersistent: context.UseSessionCookies == false);
        }
        else
        {
            if (!string.IsNullOrEmpty(options.SignInScheme))
            {
                _signInManager.AuthenticationScheme = options.SignInScheme;
            }

            await _signInManager.SignInAsync(user, isPersistent: options.IsPersistent);
        }

        await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        return Results.Redirect(ExternalSignInRedirect.Url(httpContext, context.ReturnUrl));
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

        if (context.Method == SignInMethod.External)
        {
            // Bearer SignInAsync writes the token body and starts the response.
            // Clear the external cookie first so that write is the last header change.
            await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        }

        await SignInAsync(user, context, isPersistent);

        if (context.Method == SignInMethod.External)
        {
            if (_signInManager.AuthenticationScheme == IdentityConstants.ApplicationScheme)
            {
                return Results.Redirect(ExternalSignInRedirect.Url(httpContext, context.ReturnUrl));
            }

            // Bearer sign-in already wrote AccessTokenResponse. A redirect cannot carry that body.
            return TypedResults.Empty;
        }

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

        if (context.Method == SignInMethod.External)
        {
            return await CompleteExternalAsync(httpContext, user, context);
        }

        var claimsPrincipal = await _claimsFactory.CreateAsync(user);
        var userId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("User principal is missing NameIdentifier.");
        var securityStamp = await _userManager.GetSecurityStampAsync(user);
        var session = JwtRefreshDelivery.Session(httpContext);
        var refreshToken = await _refreshTokenService.CreateAsync(userId, securityStamp);
        JwtRefreshDelivery.WriteCookie(httpContext, _refreshTokenCookieWriter, refreshToken, session);

        var response = new SimpleJwtTokenResponse
        {
            AccessToken = _accessTokenGenerator.GenerateAccessToken(claimsPrincipal),
            TokenType = "Bearer",
        };
        JwtRefreshDelivery.ApplyBody(response, refreshToken, session);

        // Same body as JWT /create. Passkey register does not add credentialId.
        return Results.Ok(response);
    }

    private async Task<IResult> CompleteExternalAsync(HttpContext httpContext, TUser user, SignInCompletionContext context)
    {
        var session = JwtRefreshDelivery.Session(httpContext);
        if (JwtRefreshDelivery.IsBody(session))
        {
            // Redirects cannot carry the refresh token. Refuse before CreateAsync so a body
            // session never stores a token the browser will not receive.
            throw new InvalidOperationException(JwtExternalBodyTransportValidator.Message);
        }

        var claimsPrincipal = await _claimsFactory.CreateAsync(user);
        var userId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("User principal is missing NameIdentifier.");
        var securityStamp = await _userManager.GetSecurityStampAsync(user);
        var refreshToken = await _refreshTokenService.CreateAsync(userId, securityStamp);
        JwtRefreshDelivery.WriteCookie(httpContext, _refreshTokenCookieWriter, refreshToken, session);
        await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        return Results.Redirect(ExternalSignInRedirect.Url(httpContext, context.ReturnUrl));
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
