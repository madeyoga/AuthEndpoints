using System.Buffers.Text;
using AuthEndpoints.Passkey;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests;

/// <summary>Counts calls and always signs in with the application cookie.</summary>
internal sealed class RecordingAlwaysSignInCompleter<TUser> : ISignInCompleter<TUser>
    where TUser : class
{
    private int _completeCalls;

    public int CompleteCalls => Volatile.Read(ref _completeCalls);

    public async Task<IResult> CompleteAsync(
        HttpContext httpContext,
        TUser user,
        SignInCompletionContext context,
        CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _completeCalls);
        var signInManager = httpContext.RequestServices.GetRequiredService<SignInManager<TUser>>();
        signInManager.AuthenticationScheme = IdentityConstants.ApplicationScheme;
        await signInManager.SignInAsync(user, isPersistent: false);
        if (context.PasskeyKind == PasskeySignInKind.Register && context.PasskeyCredentialId is { Length: > 0 })
        {
            return TypedResults.Ok(new PasskeyCredentialResponse(
                Base64Url.EncodeToString(context.PasskeyCredentialId)));
        }

        return TypedResults.Empty;
    }
}
