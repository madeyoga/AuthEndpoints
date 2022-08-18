namespace AuthEndpoints.Core;

/// <summary>
/// Use this static class to find genericBaseType of currentType
/// </summary>
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
}
