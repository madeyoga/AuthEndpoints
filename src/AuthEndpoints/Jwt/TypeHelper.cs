using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Jwt;

public static class TypeHelper
{
    public static Type? FindGenericBaseType(Type currentType, Type genericBaseType)
    {
        Type? type = currentType;
        while (type != null)
        {
            var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
            if (genericType != null && genericType == genericBaseType)
            {
                return type;
            }
            type = type.BaseType;
        }
        return null;
    }

    public static Type FindKeyType(Type userType)
    {
        var identityUserType = FindGenericBaseType(userType, typeof(IdentityUser<>));
        if (identityUserType == null)
        {
            throw NotIdentityUser(userType);
        }
        var keyType = identityUserType.GenericTypeArguments.First();
        return keyType;
    }

    // One message for every place that rejects a user type, so it always names the type and the fix.
    internal static InvalidOperationException NotIdentityUser(Type userType) =>
        new($"{userType.Name} must derive from IdentityUser<TKey> to use AuthEndpoints.");
}
