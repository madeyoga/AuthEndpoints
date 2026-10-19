using System.Reflection;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.SignIn;

/// <summary>
/// Runs a password-hash verify when no user row exists, so that path takes about as long as a wrong password.
/// The hasher receives a throwaway user. When that user cannot be constructed, a hasher failure stays a normal rejection.
/// </summary>
internal static class PasswordHashTiming<TUser>
    where TUser : class
{
    internal const string DummyUserId = "authendpoints-unknown-user";

    private static readonly TUser? DummyUser = CreateDummyUser();
    private static string? _dummyHash;

    public static void VerifyUnknownUser(IPasswordHasher<TUser> hasher, string? password)
    {
        ArgumentNullException.ThrowIfNull(hasher);

        var user = DummyUser;
        try
        {
            var hash = Volatile.Read(ref _dummyHash);
            if (hash is null)
            {
                hash = hasher.HashPassword(user!, "AuthEndpoints.UnknownUser");
                Interlocked.CompareExchange(ref _dummyHash, hash, null);
                hash = Volatile.Read(ref _dummyHash) ?? hash;
            }

            hasher.VerifyHashedPassword(user!, hash, password ?? string.Empty);
        }
        catch (Exception) when (user is null)
        {
        }
    }

    private static TUser? CreateDummyUser()
    {
        try
        {
            if (Activator.CreateInstance(typeof(TUser)) is not TUser user)
            {
                return null;
            }

            var id = user.GetType().GetProperty("Id", BindingFlags.Instance | BindingFlags.Public);
            if (id is { CanWrite: true } && id.PropertyType == typeof(string))
            {
                id.SetValue(user, DummyUserId);
            }

            return user;
        }
        catch (Exception ex) when (ex is MissingMethodException
            or MemberAccessException
            or TargetInvocationException
            or NotSupportedException
            or InvalidOperationException)
        {
            return null;
        }
    }
}
