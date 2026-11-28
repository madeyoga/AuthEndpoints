using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>
/// What every <see cref="IOAuthRequestStore{TKey}"/> must do, from its XML docs. Run against the EF Core store and an
/// in-memory one; a custom store can copy this class and implement <see cref="NewStoreAsync"/>.
/// </summary>
public abstract class OAuthRequestStoreContract : IAsyncLifetime
{
    protected static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    protected abstract Task<IOAuthRequestStore<string>> NewStoreAsync();

    public virtual Task InitializeAsync() => Task.CompletedTask;

    public virtual Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task FindLive_ReturnsOnlyTheUsersUnconsumedUnexpiredRequest()
    {
        var store = await NewStoreAsync();
        var request = Request("user-a", Now.AddMinutes(10));
        await store.CreateAsync(request, default);

        Assert.Equal(request.Id, (await store.FindLiveAsync(request.Id, "user-a", Now, default))?.Id);
        Assert.Null(await store.FindLiveAsync(request.Id, "user-b", Now, default));
        Assert.Null(await store.FindLiveAsync(request.Id, "user-a", Now.AddMinutes(10), default));
        Assert.True(await store.TryConsumeAsync(request.Id, "user-a", Now, default));
        Assert.Null(await store.FindLiveAsync(request.Id, "user-a", Now, default));
    }

    [Fact]
    public async Task ConcurrentAnswers_ToOneRequest_ExactlyOneWins()
    {
        var request = Request("user-a", Now.AddMinutes(10));
        await (await NewStoreAsync()).CreateAsync(request, default);
        var stores = new List<IOAuthRequestStore<string>>();
        for (var i = 0; i < 10; i++)
        {
            stores.Add(await NewStoreAsync());
        }

        var results = await Task.WhenAll(stores.Select(store =>
            Task.Run(() => store.TryConsumeAsync(request.Id, "user-a", Now, default))));

        Assert.Equal(1, results.Count(won => won));
    }

    [Fact]
    public async Task DeleteExpired_KeepsLiveRequests()
    {
        var store = await NewStoreAsync();
        var expired = Request("user-a", Now);
        var live = Request("user-a", Now.AddSeconds(1));
        await store.CreateAsync(expired, default);
        await store.CreateAsync(live, default);

        Assert.Equal(1, await store.DeleteExpiredAsync(Now, default));
        Assert.NotNull(await store.FindLiveAsync(live.Id, "user-a", Now, default));
    }

    protected static OAuthRequest<string> Request(string userId, DateTimeOffset expiresAt) => new()
    {
        UserId = userId,
        ClientId = "client",
        ClientName = "Client",
        RedirectUri = "https://app.example/callback",
        RedirectHost = "app.example",
        CodeChallenge = new string('c', 43),
        Scope = "api",
        Resource = "",
        CreatedAt = Now,
        ExpiresAt = expiresAt,
    };
}

/// <summary>What every <see cref="IOAuthDeveloperAppStore{TKey}"/> must do, from its XML docs.</summary>
public abstract class OAuthDeveloperAppStoreContract : IAsyncLifetime
{
    protected static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    protected abstract Task<IOAuthDeveloperAppStore<string>> NewStoreAsync();

    public virtual Task InitializeAsync() => Task.CompletedTask;

    public virtual Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task ReadsAndCounts_ByOwnerStatusIdAndClientId()
    {
        var store = await NewStoreAsync();
        var first = App("owner", "client-1", Now);
        var second = App("owner", "client-2", Now.AddMinutes(1), OAuthDeveloperAppStatus.PendingApproval);
        await store.CreateAsync(second, default);
        await store.CreateAsync(first, default);

        Assert.Equal([first.Id, second.Id], (await store.ListByOwnerAsync("owner", default)).Select(a => a.Id));
        Assert.Empty(await store.ListByOwnerAsync("user-a", default));
        Assert.Equal(2, await store.CountByOwnerAsync("owner", default));
        Assert.Equal([second.Id], (await store.ListByStatusAsync(OAuthDeveloperAppStatus.PendingApproval, default)).Select(a => a.Id));
        Assert.Equal([first.Id], (await store.FindByClientIdsAsync(["client-1", "missing"], default)).Select(a => a.Id));
        Assert.Equal([second.Id], (await store.FindByIdsAsync([second.Id, Guid.NewGuid()], default)).Select(a => a.Id));
        Assert.True(await store.IsActiveAsync(first.Id, "client-1", default));
        Assert.False(await store.IsActiveAsync(second.Id, "client-2", default));
        Assert.False(await store.IsActiveAsync(first.Id, "client-2", default));
    }

    [Fact]
    public async Task OwnerWrites_NeverUndoAnAdminDecision()
    {
        var store = await NewStoreAsync();
        var app = App("owner", "client-1", Now);
        await store.CreateAsync(app, default);
        Assert.True(await store.SetStatusAsync(app.Id, OAuthDeveloperAppStatus.Disabled, expected: null, Now, default));

        Assert.True(await store.UpdateDetailsAsync(app.Id, "Renamed", "https://renamed.example", "About", Now, default));
        Assert.True(await store.SetSecretCreatedAtAsync(app.Id, Now.AddMinutes(1), default));
        Assert.False(await store.SetStatusAsync(
            app.Id, OAuthDeveloperAppStatus.PendingApproval, OAuthDeveloperAppStatus.Active, Now, default));

        var stored = (await store.FindAsync(app.Id, default))!;
        Assert.Equal(OAuthDeveloperAppStatus.Disabled, stored.Status);
        Assert.Equal("Renamed", stored.Name);
        Assert.Equal("About", stored.Description);
        Assert.Equal(Now.AddMinutes(1), stored.SecretCreatedAt);
        Assert.Equal(Now.AddMinutes(1), stored.UpdatedAt);
    }

    [Fact]
    public async Task Delete_ReportsWhetherTheAppExisted()
    {
        var store = await NewStoreAsync();
        var app = App("owner", "client-1", Now);
        await store.CreateAsync(app, default);

        Assert.True(await store.DeleteAsync(app.Id, default));
        Assert.False(await store.DeleteAsync(app.Id, default));
        Assert.Null(await store.FindAsync(app.Id, default));
        Assert.False(await store.UpdateDetailsAsync(app.Id, "x", "https://x.example", null, Now, default));
    }

    protected static OAuthDeveloperApp<string> App(
        string ownerId,
        string clientId,
        DateTimeOffset createdAt,
        OAuthDeveloperAppStatus status = OAuthDeveloperAppStatus.Active) => new()
        {
            OwnerId = ownerId,
            ClientId = clientId,
            Name = clientId,
            HomepageUrl = "https://app.example",
            Status = status,
            CreatedAt = createdAt,
            UpdatedAt = createdAt,
        };
}

/// <summary>A SQLite file with the users the request and app rows point to. Each store gets its own context.</summary>
internal sealed class OAuthStoreDatabase : IAsyncDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"ae-oauth-store-contract-{Guid.NewGuid():N}.sqlite");
    private readonly List<TestDb> _contexts = [];

    public TestDb NewContext()
    {
        var db = new TestDb(new DbContextOptionsBuilder<TestDb>().UseSqlite($"Data Source={_path};Default Timeout=30").Options);
        lock (_contexts)
        {
            if (_contexts.Count == 0)
            {
                db.Database.EnsureCreated();
                foreach (var id in new[] { "user-a", "user-b", "owner" })
                {
                    db.Users.Add(new IdentityUser { Id = id, UserName = id });
                }

                db.SaveChanges();
                db.ChangeTracker.Clear();
            }

            _contexts.Add(db);
        }

        return db;
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

public sealed class EntityFrameworkOAuthRequestStoreContract : OAuthRequestStoreContract
{
    private readonly OAuthStoreDatabase _database = new();

    protected override Task<IOAuthRequestStore<string>> NewStoreAsync()
        => Task.FromResult<IOAuthRequestStore<string>>(new EntityFrameworkOAuthRequestStore<TestDb, string>(_database.NewContext()));

    public override async Task DisposeAsync() => await _database.DisposeAsync();
}

public sealed class InMemoryOAuthRequestStoreContract : OAuthRequestStoreContract
{
    private readonly InMemoryOAuthRequestStore _store = new();

    protected override Task<IOAuthRequestStore<string>> NewStoreAsync() => Task.FromResult<IOAuthRequestStore<string>>(_store);
}

public sealed class EntityFrameworkOAuthDeveloperAppStoreContract : OAuthDeveloperAppStoreContract
{
    private readonly OAuthStoreDatabase _database = new();

    protected override Task<IOAuthDeveloperAppStore<string>> NewStoreAsync()
        => Task.FromResult<IOAuthDeveloperAppStore<string>>(
            new EntityFrameworkOAuthDeveloperAppStore<TestDb, string>(_database.NewContext()));

    public override async Task DisposeAsync() => await _database.DisposeAsync();
}

public sealed class InMemoryOAuthDeveloperAppStoreContract : OAuthDeveloperAppStoreContract
{
    private readonly InMemoryOAuthDeveloperAppStore _store = new();

    protected override Task<IOAuthDeveloperAppStore<string>> NewStoreAsync()
        => Task.FromResult<IOAuthDeveloperAppStore<string>>(_store);
}

// Test-only stores with no EF Core behind them. One lock per store; rows are copied in and out.

internal sealed class InMemoryOAuthRequestStore : IOAuthRequestStore<string>
{
    private readonly object _gate = new();
    private readonly List<OAuthRequest<string>> _rows = [];

    public Task CreateAsync(OAuthRequest<string> request, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _rows.Add(Copy(request));
        }

        return Task.CompletedTask;
    }

    public Task<OAuthRequest<string>?> FindLiveAsync(Guid id, string userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var row = _rows.FirstOrDefault(r => Live(r, id, userId, now));
            return Task.FromResult(row is null ? null : Copy(row));
        }
    }

    public Task<bool> TryConsumeAsync(Guid id, string userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var row = _rows.FirstOrDefault(r => Live(r, id, userId, now));
            if (row is null)
            {
                return Task.FromResult(false);
            }

            row.ConsumedAt = now;
            return Task.FromResult(true);
        }
    }

    public Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(_rows.RemoveAll(r => r.ExpiresAt <= now));
        }
    }

    private static bool Live(OAuthRequest<string> row, Guid id, string userId, DateTimeOffset now)
        => row.Id == id && row.UserId == userId && row.ConsumedAt is null && row.ExpiresAt > now;

    private static OAuthRequest<string> Copy(OAuthRequest<string> row) => new()
    {
        Id = row.Id,
        UserId = row.UserId,
        ClientId = row.ClientId,
        ClientName = row.ClientName,
        RedirectUri = row.RedirectUri,
        RedirectHost = row.RedirectHost,
        CodeChallenge = row.CodeChallenge,
        Scope = row.Scope,
        State = row.State,
        Resource = row.Resource,
        Nonce = row.Nonce,
        AuthenticationMethods = row.AuthenticationMethods,
        CreatedAt = row.CreatedAt,
        ExpiresAt = row.ExpiresAt,
        ConsumedAt = row.ConsumedAt,
    };
}

internal sealed class InMemoryOAuthDeveloperAppStore : IOAuthDeveloperAppStore<string>
{
    private readonly object _gate = new();
    private readonly List<OAuthDeveloperApp<string>> _rows = [];

    public Task<IReadOnlyList<OAuthDeveloperApp<string>>> ListByOwnerAsync(string ownerId, CancellationToken cancellationToken)
        => Select(app => app.OwnerId == ownerId);

    public Task<IReadOnlyList<OAuthDeveloperApp<string>>> ListByStatusAsync(OAuthDeveloperAppStatus status, CancellationToken cancellationToken)
        => Select(app => app.Status == status);

    public async Task<OAuthDeveloperApp<string>?> FindAsync(Guid id, CancellationToken cancellationToken)
        => (await Select(app => app.Id == id)).FirstOrDefault();

    public Task<IReadOnlyList<OAuthDeveloperApp<string>>> FindByIdsAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken)
        => Select(app => ids.Contains(app.Id));

    public Task<IReadOnlyList<OAuthDeveloperApp<string>>> FindByClientIdsAsync(
        IReadOnlyCollection<string> clientIds,
        CancellationToken cancellationToken)
        => Select(app => clientIds.Contains(app.ClientId));

    public async Task<int> CountByOwnerAsync(string ownerId, CancellationToken cancellationToken)
        => (await Select(app => app.OwnerId == ownerId)).Count;

    public Task CreateAsync(OAuthDeveloperApp<string> app, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _rows.Add(Copy(app));
        }

        return Task.CompletedTask;
    }

    public Task<bool> UpdateDetailsAsync(
        Guid id,
        string name,
        string homepageUrl,
        string? description,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken)
        => Update(id, _ => true, app =>
        {
            app.Name = name;
            app.HomepageUrl = homepageUrl;
            app.Description = description;
            app.UpdatedAt = updatedAt;
        });

    public Task<bool> SetStatusAsync(
        Guid id,
        OAuthDeveloperAppStatus status,
        OAuthDeveloperAppStatus? expected,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken)
        => Update(id, app => expected is null || app.Status == expected, app =>
        {
            app.Status = status;
            app.UpdatedAt = updatedAt;
        });

    public Task<bool> SetSecretCreatedAtAsync(Guid id, DateTimeOffset secretCreatedAt, CancellationToken cancellationToken)
        => Update(id, _ => true, app =>
        {
            app.SecretCreatedAt = secretCreatedAt;
            app.UpdatedAt = secretCreatedAt;
        });

    public Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(_rows.RemoveAll(app => app.Id == id) > 0);
        }
    }

    public async Task<bool> IsActiveAsync(Guid id, string clientId, CancellationToken cancellationToken)
        => (await Select(app => app.Id == id && app.ClientId == clientId && app.Status == OAuthDeveloperAppStatus.Active)).Count > 0;

    private Task<IReadOnlyList<OAuthDeveloperApp<string>>> Select(Func<OAuthDeveloperApp<string>, bool> match)
    {
        lock (_gate)
        {
            IReadOnlyList<OAuthDeveloperApp<string>> rows = _rows.Where(match).OrderBy(app => app.CreatedAt).Select(Copy).ToList();
            return Task.FromResult(rows);
        }
    }

    private Task<bool> Update(Guid id, Func<OAuthDeveloperApp<string>, bool> condition, Action<OAuthDeveloperApp<string>> change)
    {
        lock (_gate)
        {
            var row = _rows.FirstOrDefault(app => app.Id == id);
            if (row is null || !condition(row))
            {
                return Task.FromResult(false);
            }

            change(row);
            return Task.FromResult(true);
        }
    }

    private static OAuthDeveloperApp<string> Copy(OAuthDeveloperApp<string> row) => new()
    {
        Id = row.Id,
        OwnerId = row.OwnerId,
        ClientId = row.ClientId,
        Name = row.Name,
        HomepageUrl = row.HomepageUrl,
        Description = row.Description,
        Confidential = row.Confidential,
        Status = row.Status,
        CreatedAt = row.CreatedAt,
        UpdatedAt = row.UpdatedAt,
        SecretCreatedAt = row.SecretCreatedAt,
    };
}
