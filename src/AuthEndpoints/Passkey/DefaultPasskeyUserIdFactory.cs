namespace AuthEndpoints.Passkey;

/// <summary>
/// Default <see cref="IPasskeyUserIdFactory"/> — <c>Guid.NewGuid().ToString()</c> (UUID v4).
/// </summary>
public sealed class DefaultPasskeyUserIdFactory : IPasskeyUserIdFactory
{
    public string CreateUserId() => Guid.NewGuid().ToString();
}
