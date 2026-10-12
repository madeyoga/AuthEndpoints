using System.Data.Common;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Tests;

internal static class EmailCodeFailureExceptions
{
    public static Exception SqlDeadlock()
    {
        return new DbUpdateException("deadlock", new FakeSqlException(1205));
    }

    public static Exception PostgresSerialization()
    {
        return new DbUpdateException("serialization failure", new FakePostgresException("40001"));
    }

    public static Exception Sqlite(int sqliteErrorCode)
    {
        return new DbUpdateException("sqlite", new FakeSqliteException(sqliteErrorCode));
    }

    public static Exception MySql(int number)
    {
        return new DbUpdateException("mysql", new FakeMySqlException(number));
    }

    private sealed class FakeSqlException : DbException
    {
        public FakeSqlException(int number)
            : base("deadlock victim")
        {
            Number = number;
        }

        public int Number { get; }
    }

    private sealed class FakePostgresException : DbException
    {
        public FakePostgresException(string sqlState)
            : base("could not serialize access")
        {
            SqlState = sqlState;
        }

        public override string SqlState { get; }
    }

    private sealed class FakeSqliteException : DbException
    {
        public FakeSqliteException(int sqliteErrorCode)
            : base("sqlite result")
        {
            SqliteErrorCode = sqliteErrorCode;
        }

        public int SqliteErrorCode { get; }
    }

    private sealed class FakeMySqlException : DbException
    {
        public FakeMySqlException(int number)
            : base("mysql result")
        {
            Number = number;
        }

        public int Number { get; }
    }
}
