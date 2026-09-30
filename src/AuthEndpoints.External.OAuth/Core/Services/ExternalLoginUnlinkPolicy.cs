namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Unlink is refused when it would remove the last sign-in method.
/// </summary>
internal static class ExternalLoginUnlinkPolicy
{
    internal static bool CanRemove(bool hasPassword, int passkeyCount, int loginCount)
    {
        if (loginCount < 1)
        {
            return false;
        }

        var remainingLogins = loginCount - 1;
        return hasPassword || passkeyCount > 0 || remainingLogins > 0;
    }
}
