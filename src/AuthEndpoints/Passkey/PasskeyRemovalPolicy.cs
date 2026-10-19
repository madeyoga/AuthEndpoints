using AuthEndpoints.SignIn;

namespace AuthEndpoints.Passkey;

/// <summary>
/// Deleting a passkey is refused when it would remove the last sign-in method.
/// Email code is not counted here. Callers that know whether email-code sign-in is mapped
/// use <see cref="SignInMethodPolicy"/>.
/// </summary>
internal static class PasskeyRemovalPolicy
{
    internal static bool CanRemove(bool hasPassword, int passkeyCount, int externalLoginCount)
    {
        return SignInMethodPolicy.CanRemove(
            new SignInMethodFacts(hasPassword, passkeyCount, externalLoginCount, EmailCodeSignInMapped: false, EmailConfirmed: false),
            SignInMethod.Passkey);
    }
}
