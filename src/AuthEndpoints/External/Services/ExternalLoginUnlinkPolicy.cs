using AuthEndpoints.SignIn;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Unlink is refused when it would remove the last sign-in method.
/// Email code is not counted here. Callers that know whether email-code sign-in is mapped
/// use <see cref="SignInMethodPolicy"/>.
/// </summary>
internal static class ExternalLoginUnlinkPolicy
{
    internal static bool CanRemove(bool hasPassword, int passkeyCount, int loginCount)
    {
        return SignInMethodPolicy.CanRemove(
            new SignInMethodFacts(hasPassword, passkeyCount, loginCount, EmailCodeSignInMapped: false, EmailConfirmed: false),
            SignInMethod.External);
    }
}
