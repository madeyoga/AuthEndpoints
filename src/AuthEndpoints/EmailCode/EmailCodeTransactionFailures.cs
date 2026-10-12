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
        string name = type.Name;

        // 1205 is SQL Server deadlock and MySQL lock-wait timeout. 1213 is MySQL deadlock.
        // MySqlException's name contains "SqlException".
        if (name.Contains("SqlException", StringComparison.Ordinal)
            && (PropertyEquals(exception, "Number", 1205) || PropertyEquals(exception, "Number", 1213)))
        {
            return true;
        }

        // SQLITE_BUSY is 5. SQLITE_LOCKED is 6.
        if (name.Contains("Sqlite", StringComparison.Ordinal)
            && (PropertyEquals(exception, "SqliteErrorCode", 5) || PropertyEquals(exception, "SqliteErrorCode", 6)))
        {
            return true;
        }

        return name.Contains("Postgres", StringComparison.Ordinal)
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
