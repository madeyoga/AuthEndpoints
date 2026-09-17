using System.Buffers.Text;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests;

internal sealed class RecordingAlwaysSignInCompleter<TUser> : IPasskeySignInCompleter<TUser>
    where TUser : class
{
    private int _completeCalls;

    public int CompleteCalls => Volatile.Read(ref _completeCalls);

    public async Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        PasskeySignInCompletionContext context,
        CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _completeCalls);
        var signInManager = httpContext.RequestServices.GetRequiredService<SignInManager<TUser>>();
        signInManager.AuthenticationScheme = IdentityConstants.ApplicationScheme;
        await signInManager.SignInAsync(user, isPersistent: false);
        if (context.Kind == PasskeySignInKind.Register && context.CredentialId is { Length: > 0 })
        {
            return TypedResults.Ok(new PasskeyCredentialResponse(
                Base64Url.EncodeToString(context.CredentialId)));
        }

        return TypedResults.Empty;
    }
}
