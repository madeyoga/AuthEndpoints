using AuthEndpoints.SignIn;

namespace AuthEndpoints.Passkey;

internal static class PasskeyRemovalPolicy
{
    internal static bool CanRemove(bool hasPassword, int passkeyCount, int externalLoginCount)
    {
        return SignInMethodPolicy.CanRemove(
            new SignInMethodFacts(hasPassword, passkeyCount, externalLoginCount, EmailCodeSignInMapped: false, EmailConfirmed: false),
            SignInMethod.Passkey);
    }
}
