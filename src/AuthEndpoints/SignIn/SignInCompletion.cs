using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.SignIn;

/// <summary>
/// Finishes a sign-in with the <see cref="ISignInCompleter{TUser}"/> the route selected: the name its map passed,
/// else <see cref="SignInCompletionOptions.Default"/> on a map that honors it, else the method's built-in default.
/// </summary>
internal static class SignInCompletion
{
    public static string? ExplicitName(HttpContext httpContext)
    {
        return httpContext.GetEndpoint()?.Metadata.GetMetadata<SignInCompleterSelection>()?.Name;
    }

    /// <summary>No name selected: Identity bearer, or the application cookie with <c>useCookies</c> or <c>useSessionCookies</c>.</summary>
    public static Task<IResult> CompleteEmailCodeAsync<TUser>(
        HttpContext httpContext,
        TUser user,
        bool isNewUser,
        bool? useCookies,
        bool? useSessionCookies,
        CancellationToken cancellationToken)
        where TUser : class
    {
        return CompleteAsync(
            httpContext,
            user,
            new SignInCompletionContext
            {
                Method = SignInMethod.EmailCode,
                UseCookies = useCookies,
                UseSessionCookies = useSessionCookies,
                IsNewUser = isNewUser,
            },
            SignInCompleters.IdentityBearer,
            cancellationToken);
    }

    /// <summary>No name selected: Identity bearer, or the application cookie with <c>useCookies</c> or <c>useSessionCookies</c>.</summary>
    public static Task<IResult> CompletePasskeyAsync<TUser>(
        HttpContext httpContext,
        TUser user,
        PasskeySignInKind kind,
        byte[]? credentialId,
        bool? useCookies,
        bool? useSessionCookies,
        CancellationToken cancellationToken)
        where TUser : class
    {
        return CompleteAsync(
            httpContext,
            user,
            new SignInCompletionContext
            {
                Method = SignInMethod.Passkey,
                UseCookies = useCookies,
                UseSessionCookies = useSessionCookies,
                IsNewUser = kind == PasskeySignInKind.Register,
                PasskeyKind = kind,
                PasskeyCredentialId = credentialId,
            },
            SignInCompleters.IdentityBearer,
            cancellationToken);
    }

    /// <summary>No name selected: the application cookie.</summary>
    public static Task<IResult> CompleteExternalAsync<TUser>(
        HttpContext httpContext,
        TUser user,
        ExternalLoginInfo info,
        string? returnUrl,
        bool isNewUser,
        CancellationToken cancellationToken)
        where TUser : class
    {
        return CompleteAsync(
            httpContext,
            user,
            new SignInCompletionContext
            {
                Method = SignInMethod.External,
                IsNewUser = isNewUser,
                ExternalLogin = info,
                ReturnUrl = returnUrl,
            },
            SignInCompleters.Cookie,
            cancellationToken);
    }

    private static Task<IResult> CompleteAsync<TUser>(
        HttpContext httpContext,
        TUser user,
        SignInCompletionContext context,
        string fallback,
        CancellationToken cancellationToken)
        where TUser : class
    {
        var name = ResolveName(httpContext, ExplicitName(httpContext)) ?? fallback;
        var completer = httpContext.RequestServices.GetRequiredKeyedService<ISignInCompleter<TUser>>(name);
        return completer.CompleteAsync(httpContext, user, context, cancellationToken);
    }

    private static string? ResolveName(HttpContext httpContext, string? explicitName)
    {
        if (!string.IsNullOrWhiteSpace(explicitName))
        {
            return explicitName;
        }

        if (httpContext.GetEndpoint()?.Metadata.GetMetadata<HonorSignInCompletionDefault>() is null)
        {
            return null;
        }

        var configured = httpContext.RequestServices.GetService<IOptions<SignInCompletionOptions>>()?.Value.Default;
        return string.IsNullOrWhiteSpace(configured) ? null : configured;
    }
}
