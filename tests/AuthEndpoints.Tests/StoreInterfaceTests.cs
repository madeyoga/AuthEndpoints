using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Sessions;
using AuthEndpoints.Tests.Sessions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests;

/// <summary>
/// #410: the rules run over public store interfaces, and the EF Core stores behind them keep the 4.x schema.
/// </summary>
public class StoreInterfaceTests
{
    [Fact]
    public void RefreshTokenSessionId_IsNotMappedWithoutActiveSessions()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        using var db = new TestDbContext(new DbContextOptionsBuilder<TestDbContext>().UseSqlite(connection).Options);

        var refreshTokens = db.Model.FindEntityType(typeof(RefreshToken))!;
        Assert.Null(refreshTokens.FindProperty(nameof(RefreshToken.SessionId)));
        Assert.DoesNotContain(refreshTokens.GetIndexes(), index => index.Properties.Any(p => p.Name == "SessionId"));
    }

    [Fact]
    public void RefreshTokenSessionId_WithActiveSessions_KeepsThe4xColumn()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        using var db = new ActiveSessionsDbContext(
            new DbContextOptionsBuilder<ActiveSessionsDbContext>().UseSqlite(connection).Options);

        var refreshTokens = db.Model.FindEntityType(typeof(RefreshToken))!;
        var sessionId = refreshTokens.FindProperty(nameof(RefreshToken.SessionId));
        Assert.NotNull(sessionId);
        Assert.False(sessionId.IsShadowProperty());
        Assert.True(sessionId.IsNullable);
        Assert.Equal(64, sessionId.GetMaxLength());
        var table = StoreObjectIdentifier.Table("AuthEndpointsRefreshTokens", "AuthEndpoints");
        Assert.Equal("SessionId", sessionId.GetColumnName(table));
        Assert.Contains(refreshTokens.GetIndexes(), index => index.Properties.Single().Name == "SessionId");
    }

    [Fact]
    public async Task RefreshTokenStore_WithoutSessionIdColumn_IgnoresSessionCalls()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new TestDbContext(new DbContextOptionsBuilder<TestDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        var store = new RefreshTokenStore<TestDbContext>(db);
        var token = new RefreshToken
        {
            TokenHash = "hash",
            FamilyId = "family",
            SecurityStamp = "stamp",
            UserId = "user",
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            AbsoluteExpiresAt = DateTime.UtcNow.AddDays(1),
            SessionId = "ignored",
        };
        await store.CreateAsync(token, CancellationToken.None);

        await store.SetSessionAsync(token.Id, "session", CancellationToken.None);
        Assert.Empty(await store.FindFamilySessionIdsAsync("family", CancellationToken.None));
        await store.RevokeSessionsAsync(["session"], DateTime.UtcNow, CancellationToken.None);

        var stored = await store.FindByHashAsync("hash", CancellationToken.None);
        Assert.NotNull(stored);
        Assert.Null(stored.SessionId);
        Assert.Null(stored.RevokedAt);
        Assert.Empty(db.ChangeTracker.Entries());
    }

    [Fact]
    public async Task RefreshTokenStore_TryRotate_SucceedsOnceAndLinksTheSuccessor()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new ActiveSessionsDbContext(
            new DbContextOptionsBuilder<ActiveSessionsDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        var store = new RefreshTokenStore<ActiveSessionsDbContext>(db);
        var now = DateTime.UtcNow;
        var presented = Token("presented", now, sessionId: "session");
        await store.CreateAsync(presented, CancellationToken.None);

        var first = Token("first", now, sessionId: "session");
        var second = Token("second", now, sessionId: "session");
        Assert.True(await store.TryRotateAsync(presented.Id, first, now, CancellationToken.None));
        Assert.False(await store.TryRotateAsync(presented.Id, second, now, CancellationToken.None));

        var revoked = (await store.FindByHashAsync("presented", CancellationToken.None))!;
        Assert.NotNull(revoked.RevokedAt);
        Assert.Equal(first.Id, revoked.ReplacedByTokenId);
        Assert.Equal("session", (await store.FindByHashAsync("first", CancellationToken.None))!.SessionId);
        Assert.Null(await store.FindByHashAsync("second", CancellationToken.None));
        Assert.Equal(["session"], await store.FindFamilySessionIdsAsync("family", CancellationToken.None));
        Assert.Empty(db.ChangeTracker.Entries());
    }

    [Fact]
    public async Task EfUserCreateFailureHandler_RecoversOnlyFromDbUpdateException_AndDetachesTheUser()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new TestDbContext(new DbContextOptionsBuilder<TestDbContext>().UseSqlite(connection).Options);
        var handler = new EntityFrameworkUserCreateFailureHandler<TestAppUser, TestDbContext>(db);
        var user = new TestAppUser { UserName = "a@x.com", Email = "a@x.com" };
        db.Add(user);

        Assert.False(handler.TryRecover(user, new InvalidOperationException("not a store failure")));
        Assert.Equal(EntityState.Added, db.Entry(user).State);

        Assert.True(handler.TryRecover(user, new DbUpdateException("unique index")));
        Assert.Equal(EntityState.Detached, db.Entry(user).State);
    }

    [Fact]
    public async Task EmailCodeService_RunsOverAnyStore()
    {
        // A store with no EF Core behind it: the service hashes the address and code, and the store sees only hashes.
        var store = new RecordingEmailCodeStore();
        var service = new EmailCodeService(
            store,
            TimeProvider.System,
            Options.Create(new EmailCodeOptions()),
            new Microsoft.AspNetCore.Identity.UpperInvariantLookupNormalizer());

        var issued = await service.IssueAsync("A@x.com ", "user", "stamp", EmailCodeRowPurpose.SignIn);

        Assert.False(issued.Suppressed);
        var entry = Assert.Single(store.Issued);
        Assert.Equal(issued.EmailHash, entry.EmailHash);
        Assert.DoesNotContain("x.com", entry.EmailHash, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(issued.Code, entry.CodeHash);
        Assert.True(service.CodeMatches(entry, issued.Code));
        Assert.NotNull(store.Rules);
        Assert.Equal(new EmailCodeOptions().MaxAttempts, store.Rules.Liveness.MaxAttempts);
        Assert.Equal(store.Rules.Liveness.Now - new EmailCodeOptions().ResendCooldown, store.Rules.CooldownSince);
    }

    [Fact]
    public void EfStores_AreTheRegisteredDefaults()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<ActiveSessionsDbContext>(options => options.UseSqlite("Data Source=:memory:"));
        services.AddAuthEndpoints<TestAppUser, ActiveSessionsDbContext>()
            .AddEmailCode()
            .AddJwt(jwt =>
            {
                jwt.Issuer = "https://issuer.test";
                jwt.Audience = "https://audience.test";
                jwt.SigningOptions.SymmetricKey = new string('k', 64);
            });
        services.AddActiveSessions<TestAppUser, ActiveSessionsDbContext>();

        Assert.Contains(services, d => d.ServiceType == typeof(IEmailCodeStore));
        Assert.Contains(services, d => d.ServiceType == typeof(IRefreshTokenStore));
        Assert.Contains(services, d => d.ServiceType == typeof(IActiveSessionStore));
        Assert.Contains(services, d => d.ServiceType == typeof(IUserCreateFailureHandler<TestAppUser>));
    }

    private static RefreshToken Token(string hash, DateTime now, string? sessionId) => new()
    {
        TokenHash = hash,
        FamilyId = "family",
        SecurityStamp = "stamp",
        UserId = "user",
        ExpiresAt = now.AddDays(1),
        AbsoluteExpiresAt = now.AddDays(1),
        SessionId = sessionId,
    };

    private sealed class RecordingEmailCodeStore : IEmailCodeStore
    {
        public List<EmailCodeEntry> Issued { get; } = [];

        public EmailCodeIssueRules? Rules { get; private set; }

        public Task<EmailCodeIssueStatus> IssueAsync(EmailCodeEntry entry, EmailCodeIssueRules rules, CancellationToken cancellationToken)
        {
            Issued.Add(entry);
            Rules = rules;
            return Task.FromResult(EmailCodeIssueStatus.Issued);
        }

        public Task<EmailCodeEntry?> FindLiveByEmailAsync(string emailHash, EmailCodeRowPurpose purpose, string? userId, EmailCodeLiveness liveness, CancellationToken cancellationToken)
            => Task.FromResult<EmailCodeEntry?>(null);

        public Task<EmailCodeEntry?> FindLiveByLinkTokenAsync(string linkTokenHash, EmailCodeLiveness liveness, CancellationToken cancellationToken)
            => Task.FromResult<EmailCodeEntry?>(null);

        public Task<bool> TryReserveAttemptAsync(string id, EmailCodeLiveness liveness, CancellationToken cancellationToken)
            => Task.FromResult(false);

        public Task<bool> TryReleaseAttemptAsync(string id, CancellationToken cancellationToken)
            => Task.FromResult(false);

        public Task<bool> TryConsumeAsync(string id, EmailCodeLiveness liveness, bool attemptReserved, CancellationToken cancellationToken)
            => Task.FromResult(false);

        public Task<bool> TryUnconsumeAsync(string id, CancellationToken cancellationToken)
            => Task.FromResult(false);

        public Task<int> CountIssuedSinceAsync(string emailHash, EmailCodeRowPurpose purpose, DateTime since, CancellationToken cancellationToken)
            => Task.FromResult(0);
    }
}
