using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.SignIn;

/// <summary>
/// Runs a password-hash verify when no user row exists, so that path takes about as long as a wrong password.
/// </summary>
internal static class PasswordHashTiming<TUser>
    where TUser : class
{
    private static string? _dummyHash;

    public static void VerifyUnknownUser(IPasswordHasher<TUser> hasher, string? password)
    {
        ArgumentNullException.ThrowIfNull(hasher);

        var hash = Volatile.Read(ref _dummyHash);
        if (hash is null)
        {
            hash = hasher.HashPassword(default!, "AuthEndpoints.UnknownUser");
            Interlocked.CompareExchange(ref _dummyHash, hash, null);
            hash = Volatile.Read(ref _dummyHash) ?? hash;
        }

        hasher.VerifyHashedPassword(default!, hash, password ?? string.Empty);
    }
}
