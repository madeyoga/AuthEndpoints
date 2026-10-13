namespace AuthEndpoints;

/// <summary>
/// Proof that a sign-in completer is finishing. The method has already accepted the proof.
/// </summary>
public enum SignInMethod
{
    Password = 0,
    EmailCode = 1,
    Passkey = 2,
    External = 3,
}
