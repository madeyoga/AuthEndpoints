using System.ComponentModel;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Passkey;

internal static class UserIdHelper
{
    public static string CreateUserIdString(Type userType, IPasskeyUserIdFactory? factory = null)
    {
        var keyType = TypeHelper.FindKeyType(userType)
            ?? throw new InvalidOperationException("Generic type TUser is not IdentityUser.");

        if (keyType == typeof(string) || keyType == typeof(Guid))
        {
            return factory?.CreateUserId() ?? Guid.NewGuid().ToString();
        }

        throw new NotSupportedException(
            "Passwordless passkey registration requires IdentityUser with a string or Guid key " +
            "so the user id can be chosen before CreateAsync.");
    }

    public static void SetUserId<TUser>(TUser user, string userId)
        where TUser : class
    {
        var identityUserType = TypeHelper.FindGenericBaseType(typeof(TUser), typeof(IdentityUser<>))
            ?? throw new InvalidOperationException("Generic type TUser is not IdentityUser.");

        var keyType = identityUserType.GenericTypeArguments[0];
        var idProperty = identityUserType.GetProperty(nameof(IdentityUser.Id))
            ?? throw new InvalidOperationException("Could not find IdentityUser.Id property.");

        object convertedId;
        if (keyType == typeof(string))
        {
            convertedId = userId;
        }
        else
        {
            var converter = TypeDescriptor.GetConverter(keyType);
            convertedId = converter.ConvertFromInvariantString(userId)
                ?? throw new InvalidOperationException($"Could not convert user id '{userId}' to {keyType}.");
        }

        idProperty.SetValue(user, convertedId);
    }
}
