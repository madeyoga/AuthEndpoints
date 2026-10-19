namespace AuthEndpoints.SignIn;

internal readonly record struct SignInMethodFacts(
    bool HasPassword,
    int PasskeyCount,
    int ExternalLoginCount,
    bool EmailCodeSignInMapped,
    bool EmailConfirmed);

internal static class SignInMethodPolicy
{
    internal static bool CanRemove(SignInMethodFacts facts, SignInMethod removing)
    {
        var emailCode = facts.EmailCodeSignInMapped && facts.EmailConfirmed ? 1 : 0;
        var password = facts.HasPassword ? 1 : 0;

        if (removing == SignInMethod.Passkey)
        {
            if (facts.PasskeyCount < 1)
            {
                return false;
            }

            return password + (facts.PasskeyCount - 1) + facts.ExternalLoginCount + emailCode >= 1;
        }

        if (removing == SignInMethod.External)
        {
            if (facts.ExternalLoginCount < 1)
            {
                return false;
            }

            return password + facts.PasskeyCount + (facts.ExternalLoginCount - 1) + emailCode >= 1;
        }

        return false;
    }
}
