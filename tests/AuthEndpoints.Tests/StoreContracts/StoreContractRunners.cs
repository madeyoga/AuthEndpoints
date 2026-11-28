using AuthEndpoints.EmailCode;
using AuthEndpoints.Jwt;
using AuthEndpoints.Sessions;
using AuthEndpoints.Tests.Sessions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Tests.StoreContracts;

/// <summary>
/// A SQLite file shared by every store a test creates. Each store gets its own <see cref="DbContext"/>, so the race tests
/// run on separate connections, like concurrent requests.
/// </summary>
internal sealed class SqliteStoreDatabase : IAsyncDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"ae-store-contract-{Guid.NewGuid():N}.sqlite");
    private readonly List<ActiveSessionsDbContext> _contexts = [];

    // UseRefreshToken, UseEmailCodes and UseActiveSessions: every AuthEndpoints table, with the refresh-token SessionId.
    public async Task<ActiveSessionsDbContext> NewContextAsync()
    {
        var options = new DbContextOptionsBuilder<ActiveSessionsDbContext>()
            .UseSqlite($"Data Source={_path};Default Timeout=30")
            .Options;
        var db = new ActiveSessionsDbContext(options);
        lock (_contexts)
        {
            if (_contexts.Count == 0)
            {
                db.Database.EnsureCreated();
            }

            _contexts.Add(db);
        }

        return await Task.FromResult(db);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var db in _contexts)
        {
            await db.DisposeAsync();
        }

        SqliteConnection.ClearAllPools();
        File.Delete(_path);
    }
}

public sealed class EntityFrameworkEmailCodeStoreContract : EmailCodeStoreContract
{
    private readonly SqliteStoreDatabase _database = new();

    protected override async Task<IEmailCodeStore> NewStoreAsync()
        => new EmailCodeStore<ActiveSessionsDbContext>(await _database.NewContextAsync());

    public override async Task DisposeAsync() => await _database.DisposeAsync();
}

public sealed class InMemoryEmailCodeStoreContract : EmailCodeStoreContract
{
    private readonly InMemoryEmailCodeStore _store = new();

    protected override Task<IEmailCodeStore> NewStoreAsync() => Task.FromResult<IEmailCodeStore>(_store);
}

public sealed class EntityFrameworkRefreshTokenStoreContract : RefreshTokenStoreContract
{
    private readonly SqliteStoreDatabase _database = new();

    protected override async Task<IRefreshTokenStore> NewStoreAsync()
        => new RefreshTokenStore<ActiveSessionsDbContext>(await _database.NewContextAsync());

    public override async Task DisposeAsync() => await _database.DisposeAsync();
}

public sealed class InMemoryRefreshTokenStoreContract : RefreshTokenStoreContract
{
    private readonly InMemoryRefreshTokenStore _store = new();

    protected override Task<IRefreshTokenStore> NewStoreAsync() => Task.FromResult<IRefreshTokenStore>(_store);
}

public sealed class EntityFrameworkActiveSessionStoreContract : ActiveSessionStoreContract
{
    private readonly SqliteStoreDatabase _database = new();

    protected override async Task<IActiveSessionStore> NewStoreAsync()
        => new ActiveSessionStore<ActiveSessionsDbContext>(await _database.NewContextAsync());

    public override async Task DisposeAsync() => await _database.DisposeAsync();
}

public sealed class InMemoryActiveSessionStoreContract : ActiveSessionStoreContract
{
    private readonly InMemoryActiveSessionStore _store = new();

    protected override Task<IActiveSessionStore> NewStoreAsync() => Task.FromResult<IActiveSessionStore>(_store);
}
