using AuthEndpoints.EmailCode;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.SignIn;

internal static class SignInCompletion
{
    public static string? ExplicitName(HttpContext httpContext)
    {
        return httpContext.GetEndpoint()?.Metadata.GetMetadata<SignInCompleterSelection>()?.Name;
    }

    public static async Task<IResult> CompleteEmailCodeAsync<TUser>(
        HttpContext httpContext,
        TUser user,
        IEmailCodeSignInCompleter<TUser> legacy,
        bool isNewUser,
        bool? useCookies,
        bool? useSessionCookies,
        CancellationToken cancellationToken)
        where TUser : class
    {
        var explicitName = ExplicitName(httpContext);
        if (explicitName is null && LegacySignInCompleters.EmailCodeWins(httpContext.RequestServices, legacy))
        {
            return await legacy.CompleteAsync(
                httpContext,
                user,
                new EmailCodeSignInContext
                {
                    UseCookies = useCookies,
                    UseSessionCookies = useSessionCookies,
                    IsNewUser = isNewUser,
                },
                cancellationToken);
        }

        var name = ResolveName(httpContext, explicitName);
        if (name is null)
        {
            return await legacy.CompleteAsync(
                httpContext,
                user,
                new EmailCodeSignInContext
                {
                    UseCookies = useCookies,
                    UseSessionCookies = useSessionCookies,
                    IsNewUser = isNewUser,
                },
                cancellationToken);
        }

        var completer = httpContext.RequestServices.GetRequiredKeyedService<ISignInCompleter<TUser>>(name);
        return await completer.CompleteAsync(
            httpContext,
            user,
            new SignInCompletionContext
            {
                Method = SignInMethod.EmailCode,
                UseCookies = useCookies,
                UseSessionCookies = useSessionCookies,
                IsNewUser = isNewUser,
            },
            cancellationToken);
    }

    public static async Task<IResult> CompletePasskeyAsync<TUser>(
        HttpContext httpContext,
        TUser user,
        PasskeySignInCompletionContext legacyContext,
        IPasskeySignInCompleter<TUser> legacy,
        CancellationToken cancellationToken)
        where TUser : class
    {
        var explicitName = ExplicitName(httpContext);
        if (explicitName is null && LegacySignInCompleters.PasskeyWins(httpContext.RequestServices, legacy))
        {
            return await legacy.CompleteAsync(httpContext, user, legacyContext, cancellationToken);
        }

        var name = ResolveName(httpContext, explicitName);
        if (name is null)
        {
            return await legacy.CompleteAsync(httpContext, user, legacyContext, cancellationToken);
        }

        var completer = httpContext.RequestServices.GetRequiredKeyedService<ISignInCompleter<TUser>>(name);
        return await completer.CompleteAsync(
            httpContext,
            user,
            new SignInCompletionContext
            {
                Method = SignInMethod.Passkey,
                UseCookies = legacyContext.UseCookies,
                UseSessionCookies = legacyContext.UseSessionCookies,
                IsNewUser = legacyContext.Kind == PasskeySignInKind.Register,
                PasskeyKind = legacyContext.Kind,
                PasskeyCredentialId = legacyContext.CredentialId,
            },
            cancellationToken);
    }

    /// <summary>
    /// Map argument, then <see cref="SignInCompletionOptions.Default"/>.
    /// Null keeps the 3.x per-method completer (Identity bearer for email code and passkey).
    /// </summary>
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
