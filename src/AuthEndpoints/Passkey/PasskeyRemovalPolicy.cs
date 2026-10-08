namespace AuthEndpoints.Passkey;

/// <summary>
/// Deleting a passkey is refused when it would remove the last sign-in method.
/// Mirrors <c>ExternalLoginUnlinkPolicy.CanRemove</c> with passkeys and external logins swapped.
/// </summary>
internal static class PasskeyRemovalPolicy
{
    internal static bool CanRemove(bool hasPassword, int passkeyCount, int externalLoginCount)
    {
        if (passkeyCount < 1)
        {
            return false;
        }

        return hasPassword || externalLoginCount > 0 || passkeyCount > 1;
    }
}
