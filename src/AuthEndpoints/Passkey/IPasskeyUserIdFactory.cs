namespace AuthEndpoints.Passkey;

/// <summary>
/// Mints the user id embedded in WebAuthn creation options during passwordless
/// passkey registration. The default is <c>Guid.NewGuid().ToString()</c> (UUID v4).
/// </summary>
public interface IPasskeyUserIdFactory
{
    /// <summary>
    /// Returns the user id string used as the WebAuthn user handle for a new account.
    /// Register later copies this value from the attestation <c>userEntity.Id</c>.
    /// </summary>
    string CreateUserId();
}
