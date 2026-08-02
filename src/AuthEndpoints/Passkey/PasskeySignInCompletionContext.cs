namespace AuthEndpoints.Passkey;

public enum PasskeySignInKind
{
    Login,
    Register
}

/// <summary>
/// Context for <see cref="IPasskeySignInCompleter{TUser}"/> after a successful WebAuthn ceremony.
/// </summary>
public sealed class PasskeySignInCompletionContext
{
    public required PasskeySignInKind Kind { get; init; }

    /// <summary>
    /// Honored by <see cref="IdentityPasskeySignInCompleter{TUser}"/> only.
    /// </summary>
    public bool? UseCookies { get; init; }

    /// <summary>
    /// Honored by <see cref="IdentityPasskeySignInCompleter{TUser}"/> only.
    /// </summary>
    public bool? UseSessionCookies { get; init; }

    /// <summary>
    /// Credential id from passwordless registration (register ceremonies only).
    /// </summary>
    public byte[]? CredentialId { get; init; }
}
