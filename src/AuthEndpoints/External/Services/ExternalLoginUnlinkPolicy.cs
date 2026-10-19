using AuthEndpoints.SignIn;

namespace AuthEndpoints.External.OAuth;

internal static class ExternalLoginUnlinkPolicy
{
    internal static bool CanRemove(bool hasPassword, int passkeyCount, int loginCount)
    {
        return SignInMethodPolicy.CanRemove(
            new SignInMethodFacts(hasPassword, passkeyCount, loginCount, EmailCodeSignInMapped: false, EmailConfirmed: false),
            SignInMethod.External);
    }
}
