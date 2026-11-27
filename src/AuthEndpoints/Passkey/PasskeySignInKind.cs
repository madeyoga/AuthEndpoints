namespace AuthEndpoints.Passkey;

/// <summary>Which passkey ceremony finished: <see cref="SignInCompletionContext.PasskeyKind"/>.</summary>
public enum PasskeySignInKind
{
    Login,
    Register
}
