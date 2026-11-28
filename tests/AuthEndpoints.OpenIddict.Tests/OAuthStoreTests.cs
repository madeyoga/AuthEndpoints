using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>
/// #410: the OAuth server reads and writes its own rows through public store interfaces. These pin the EF Core stores'
/// contract, and the message when a store is missing.
/// </summary>
public sealed class OAuthStoreTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private TestDb _db = null!;

    public async Task InitializeAsync()
    {
        await _connection.OpenAsync();
        _db = new TestDb(new DbContextOptionsBuilder<TestDb>().UseSqlite(_connection).Options);
        await _db.Database.EnsureCreatedAsync();
        // The request and app tables have foreign keys to the users table (UseAuthEndpointsOpenIddict's default).
        foreach (var id in new[] { "user-a", "user-b", "owner" })
        {
            _db.Users.Add(new IdentityUser { Id = id, UserName = id });
        }

        await _db.SaveChangesAsync();
        _db.ChangeTracker.Clear();
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
        await _connection.DisposeAsync();
    }

    [Fact]
    public async Task RequestStore_FindsOnlyTheUsersLiveRequest_AndConsumesItOnce()
    {
        var store = new EntityFrameworkOAuthRequestStore<TestDb, string>(_db);
        var request = Request("user-a", expiresAt: Now.AddMinutes(10));
        await store.CreateAsync(request, CancellationToken.None);

        Assert.NotNull(await store.FindLiveAsync(request.Id, "user-a", Now, CancellationToken.None));
        Assert.Null(await store.FindLiveAsync(request.Id, "user-b", Now, CancellationToken.None));
        Assert.Null(await store.FindLiveAsync(request.Id, "user-a", Now.AddMinutes(10), CancellationToken.None));

        Assert.False(await store.TryConsumeAsync(request.Id, "user-b", Now, CancellationToken.None));
        Assert.True(await store.TryConsumeAsync(request.Id, "user-a", Now, CancellationToken.None));
        Assert.False(await store.TryConsumeAsync(request.Id, "user-a", Now, CancellationToken.None));
        Assert.Null(await store.FindLiveAsync(request.Id, "user-a", Now, CancellationToken.None));
        Assert.Empty(_db.ChangeTracker.Entries());
    }

    [Fact]
    public async Task RequestStore_DeletesOnlyExpiredRequests()
    {
        var store = new EntityFrameworkOAuthRequestStore<TestDb, string>(_db);
        var expired = Request("user-a", expiresAt: Now);
        var live = Request("user-a", expiresAt: Now.AddSeconds(1));
        await store.CreateAsync(expired, CancellationToken.None);
        await store.CreateAsync(live, CancellationToken.None);

        Assert.Equal(1, await store.DeleteExpiredAsync(Now, CancellationToken.None));
        Assert.Equal([live.Id], await _db.Set<OAuthRequest<string>>().Select(r => r.Id).ToListAsync());
    }

    [Fact]
    public async Task DeveloperAppStore_StoresEveryValue_AndLeavesNothingTracked()
    {
        var store = new EntityFrameworkOAuthDeveloperAppStore<TestDb, string>(_db);
        var app = App("owner", "client-1", Now);
        var other = App("owner", "client-2", Now.AddMinutes(1));
        await store.CreateAsync(app, CancellationToken.None);
        await store.CreateAsync(other, CancellationToken.None);

        Assert.True(await store.UpdateDetailsAsync(app.Id, "Renamed", "https://renamed.example", "New", Now.AddHours(1), CancellationToken.None));
        Assert.True(await store.SetStatusAsync(app.Id, OAuthDeveloperAppStatus.Disabled, expected: null, Now.AddHours(1), CancellationToken.None));
        Assert.True(await store.SetSecretCreatedAtAsync(app.Id, Now.AddHours(1), CancellationToken.None));
        Assert.False(await store.UpdateDetailsAsync(Guid.NewGuid(), "x", "https://x.example", null, Now, CancellationToken.None));

        var stored = (await store.FindAsync(app.Id, CancellationToken.None))!;
        Assert.Equal("Renamed", stored.Name);
        Assert.Equal("https://renamed.example", stored.HomepageUrl);
        Assert.Equal("New", stored.Description);
        Assert.Equal(OAuthDeveloperAppStatus.Disabled, stored.Status);
        Assert.Equal(Now.AddHours(1), stored.UpdatedAt);
        Assert.Equal(Now.AddHours(1), stored.SecretCreatedAt);

        Assert.Equal([app.Id, other.Id], (await store.ListByOwnerAsync("owner", CancellationToken.None)).Select(a => a.Id));
        Assert.Equal(2, await store.CountByOwnerAsync("owner", CancellationToken.None));
        Assert.Equal([other.Id], (await store.ListByStatusAsync(OAuthDeveloperAppStatus.Active, CancellationToken.None)).Select(a => a.Id));
        Assert.Equal([other.Id], (await store.FindByClientIdsAsync(["client-2", "missing"], CancellationToken.None)).Select(a => a.Id));
        Assert.Equal([app.Id], (await store.FindByIdsAsync([app.Id, Guid.NewGuid()], CancellationToken.None)).Select(a => a.Id));

        Assert.False(await store.IsActiveAsync(app.Id, "client-1", CancellationToken.None));
        Assert.True(await store.IsActiveAsync(other.Id, "client-2", CancellationToken.None));
        Assert.False(await store.IsActiveAsync(other.Id, "client-1", CancellationToken.None));

        Assert.True(await store.DeleteAsync(app.Id, CancellationToken.None));
        Assert.False(await store.DeleteAsync(app.Id, CancellationToken.None));
        Assert.Empty(_db.ChangeTracker.Entries());
    }

    [Fact]
    public async Task DeveloperAppStore_OwnerWrites_NeverUndoAnAdminDisable()
    {
        // The owner's request loaded the app while it was active; an admin disables it before the owner saves.
        var store = new EntityFrameworkOAuthDeveloperAppStore<TestDb, string>(_db);
        var app = App("owner", "client-1", Now);
        await store.CreateAsync(app, CancellationToken.None);
        var loadedByOwner = (await store.FindAsync(app.Id, CancellationToken.None))!;
        Assert.Equal(OAuthDeveloperAppStatus.Active, loadedByOwner.Status);
        Assert.True(await store.SetStatusAsync(app.Id, OAuthDeveloperAppStatus.Disabled, expected: null, Now, CancellationToken.None));

        await store.UpdateDetailsAsync(app.Id, "Renamed", loadedByOwner.HomepageUrl, null, Now, CancellationToken.None);
        await store.SetSecretCreatedAtAsync(app.Id, Now, CancellationToken.None);
        // An edit that sends an active app back to review is a compare-and-set, and loses to the admin.
        Assert.False(await store.SetStatusAsync(
            app.Id, OAuthDeveloperAppStatus.PendingApproval, OAuthDeveloperAppStatus.Active, Now, CancellationToken.None));

        var stored = (await store.FindAsync(app.Id, CancellationToken.None))!;
        Assert.Equal(OAuthDeveloperAppStatus.Disabled, stored.Status);
        Assert.Equal("Renamed", stored.Name);
        Assert.False(await store.IsActiveAsync(app.Id, "client-1", CancellationToken.None));
    }

    [Fact]
    public async Task ServerQueries_ReadRedirectUris_ForStoredClientsOnly()
    {
        var queries = new EntityFrameworkOAuthServerQueries<TestDb>(_db);
        _db.Add(new global::OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication
        {
            ClientId = "client-1",
            RedirectUris = "[\"https://app.example/callback\"]",
            PostLogoutRedirectUris = "[\"https://app.example/\"]",
        });
        await _db.SaveChangesAsync();
        _db.ChangeTracker.Clear();

        var uris = await queries.FindRedirectUrisAsync(["client-1", "missing"], CancellationToken.None);

        var only = Assert.Single(uris);
        Assert.Equal("client-1", only.Key);
        Assert.Equal(["https://app.example/callback"], only.Value.RedirectUris);
        Assert.Equal(["https://app.example/"], only.Value.PostLogoutRedirectUris);
    }

    [Fact]
    public void EnsureStores_NamesTheMissingStore()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<TestDb>(options => options.UseSqlite(_connection));
        services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<TestDb>();
        services.AddOAuthServer<IdentityUser, TestDb>(options => options.Issuer = new Uri("https://issuer.example/"));
        services.RemoveAll<IOAuthRequestStore<string>>();
        using var provider = services.BuildServiceProvider();

        var error = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredService<OAuthServerMarker>().EnsureStores(provider));
        Assert.Contains("needs an IOAuthRequestStore<String>", error.Message, StringComparison.Ordinal);
    }

    private static OAuthRequest<string> Request(string userId, DateTimeOffset expiresAt) => new()
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

    private static OAuthDeveloperApp<string> App(string ownerId, string clientId, DateTimeOffset createdAt) => new()
    {
        OwnerId = ownerId,
        ClientId = clientId,
        Name = clientId,
        HomepageUrl = "https://app.example",
        Status = OAuthDeveloperAppStatus.Active,
        CreatedAt = createdAt,
        UpdatedAt = createdAt,
    };
}
