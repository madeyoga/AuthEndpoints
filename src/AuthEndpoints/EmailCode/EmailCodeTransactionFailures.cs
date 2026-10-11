using System.Reflection;

namespace AuthEndpoints.EmailCode;

internal static class EmailCodeTransactionFailures
{
    public static bool IsDeadlockOrSerializationFailure(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (IsProviderFailure(current))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsProviderFailure(Exception exception)
    {
        Type type = exception.GetType();
        if (type.Name.Contains("SqlException", StringComparison.Ordinal)
            && PropertyEquals(exception, "Number", 1205))
        {
            return true;
        }

        return type.Name.Contains("Postgres", StringComparison.Ordinal)
            && (PropertyEquals(exception, "SqlState", "40001")
                || PropertyEquals(exception, "SqlState", "40P01"));
    }

    private static bool PropertyEquals<T>(Exception exception, string name, T expected)
        where T : notnull
    {
        PropertyInfo? property = exception.GetType().GetProperty(name);
        return property?.GetValue(exception) is T value && value.Equals(expected);
    }
}
