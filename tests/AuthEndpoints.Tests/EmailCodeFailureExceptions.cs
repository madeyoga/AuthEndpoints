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
}
