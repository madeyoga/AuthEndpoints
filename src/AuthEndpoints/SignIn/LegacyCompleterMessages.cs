namespace AuthEndpoints.SignIn;

internal static class LegacyCompleterMessages
{
    public const string Obsolete =
        "Implement ISignInCompleter<TUser> and register it with AddSignInCompleter<TUser, TCompleter>(name). Pass that name to the sign-in map, or set SignInCompletionOptions.Default. Removed in 5.0.";
}
