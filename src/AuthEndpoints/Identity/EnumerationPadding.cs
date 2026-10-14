using System.Reflection;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Identity;

/// <summary>
/// Work the unknown-account branch of an enumeration-sensitive route runs so it
/// costs about as much as the branch that has an account. Always on. There is no option to skip it.
/// </summary>
internal static class EnumerationPadding
{
    private const string Purpose = "AuthEndpoints.EnumerationPadding.v1";

    public static string Protect(IDataProtectionProvider provider, string material)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentException.ThrowIfNullOrEmpty(material);
        var protector = provider.CreateProtector(Purpose);
        return Convert.ToBase64String(protector.Protect(Encoding.UTF8.GetBytes(material)));
    }

    /// <summary>
    /// Mints a password-reset token for an unsaved user. The token is not for any stored account.
    /// Falls back to <see cref="Protect"/> when the user type has no string or <see cref="Guid"/> key.
    /// </summary>
    public static async Task<string> CreateDecoyPasswordResetTokenAsync<TUser>(
        UserManager<TUser> userManager,
        IUserStore<TUser> store,
        IDataProtectionProvider dataProtection,
        string email)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(userManager);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrEmpty(email);

        var user = new TUser();
        try
        {
            if (!TryAssignEphemeralId(user))
            {
                return Protect(dataProtection, email);
            }

            if (store is IUserSecurityStampStore<TUser> stamps)
            {
                await stamps.SetSecurityStampAsync(user, Guid.NewGuid().ToString("N"), CancellationToken.None);
            }

            return await userManager.GeneratePasswordResetTokenAsync(user);
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or FormatException or ArgumentException)
        {
            return Protect(dataProtection, email);
        }
    }

    private static bool TryAssignEphemeralId<TUser>(TUser user)
        where TUser : class
    {
        var identityUserType = FindIdentityUser(typeof(TUser));
        if (identityUserType is null)
        {
            return false;
        }

        var keyType = identityUserType.GenericTypeArguments[0];
        var idProperty = identityUserType.GetProperty("Id", BindingFlags.Instance | BindingFlags.Public);
        if (idProperty is null || !idProperty.CanWrite)
        {
            return false;
        }

        if (keyType == typeof(string))
        {
            idProperty.SetValue(user, Guid.NewGuid().ToString("N"));
            return true;
        }

        if (keyType == typeof(Guid))
        {
            idProperty.SetValue(user, Guid.NewGuid());
            return true;
        }

        return false;
    }

    private static Type? FindIdentityUser(Type current)
    {
        var type = current;
        while (type is not null)
        {
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(IdentityUser<>))
            {
                return type;
            }

            type = type.BaseType;
        }

        return null;
    }
}
