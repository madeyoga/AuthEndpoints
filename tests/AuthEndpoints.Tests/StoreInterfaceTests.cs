using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Sessions;
using AuthEndpoints.Tests.Sessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
    public async Task RefreshTokenService_NeverHandsTheRawTokenToTheStore()
    {
        var store = new RecordingRefreshTokenStore();
        var service = new RefreshTokenService(store, TimeProvider.System, Options.Create(new SimpleJwtOptions()));

        var created = await service.CreateAsync("user", "stamp");
        var rotated = await service.RotateAsync(created, "stamp");

        Assert.NotNull(created.Token);
        Assert.NotNull(rotated?.Token);
        Assert.Equal(2, store.Received.Count);
        Assert.All(store.Received, token =>
        {
            Assert.Null(token.TokenOnArrival);
            Assert.Equal(64, token.Hash.Length);
        });
        Assert.Equal(RefreshTokenService.HashToken(created.Token), store.Received[0].Hash);
        Assert.Equal(RefreshTokenService.HashToken(rotated!.Token!), store.Received[1].Hash);
    }

    [Fact]
    public void EfStores_AreTheRegisteredDefaults()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<ActiveSessionsDbContext>(options => options.UseSqlite("Data Source=:memory:"));
        services.AddAuthEndpoints<TestAppUser>().AddEntityFrameworkStores<ActiveSessionsDbContext>()
            .AddEmailCode()
            .AddJwt(jwt =>
            {
                jwt.Issuer = "https://issuer.test";
                jwt.Audience = "https://audience.test";
                jwt.SigningOptions.SymmetricKey = new string('k', 64);
            });
        services.AddAuthEndpointsEntityFrameworkStores<TestAppUser, ActiveSessionsDbContext>().AddActiveSessions<TestAppUser>();

        Assert.Contains(services, d => d.ServiceType == typeof(IEmailCodeStore));
        Assert.Contains(services, d => d.ServiceType == typeof(IRefreshTokenStore));
        Assert.Contains(services, d => d.ServiceType == typeof(IActiveSessionStore));
        Assert.Contains(services, d => d.ServiceType == typeof(IUserCreateFailureHandler<TestAppUser>));
    }

    [Fact]
    public void Core_DoesNotReferenceEntityFrameworkCore()
    {
        var references = typeof(AuthEndpointsOptions).Assembly.GetReferencedAssemblies().Select(a => a.Name!).ToList();
        Assert.DoesNotContain(references, name => name.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.Ordinal));
        Assert.DoesNotContain(references, name => name.StartsWith("Microsoft.AspNetCore.Identity.EntityFrameworkCore", StringComparison.Ordinal));
    }

    [Fact]
    public void MapAuthEndpoints_WithoutStores_NamesTheMissingUserStore()
    {
        using var app = Host(builder => builder.Services.AddAuthEndpoints<TestAppUser>().AddPassword());

        var error = Assert.Throws<InvalidOperationException>(() => app.MapAuthEndpoints<TestAppUser>("/auth", AuthEndpointsSession.Cookie));
        Assert.Contains("IUserStore<TestAppUser>", error.Message, StringComparison.Ordinal);
        Assert.Contains("AuthEndpoints.EntityFrameworkCore", error.Message, StringComparison.Ordinal);
        Assert.Contains("AddEntityFrameworkStores<TContext>()", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MapEmailCode_WithIdentityStoresOnly_NamesTheMissingEmailCodeStore()
    {
        using var app = Host(builder =>
        {
            builder.Services.AddAuthEndpointsIdentity<TestAppUser>().AddEntityFrameworkStores<TestDbContext>();
            builder.Services.AddEmailCodeEndpoints<TestAppUser>();
        });

        var error = Assert.Throws<InvalidOperationException>(() => app.MapEmailCodeEndpoints<TestAppUser>());
        Assert.Contains("needs an IEmailCodeStore", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MapJwt_WithoutRefreshTokenStore_NamesIt_ButACustomServiceNeedsNone()
    {
        using var missing = Host(builder =>
        {
            builder.Services.AddAuthEndpointsIdentity<TestAppUser>().AddEntityFrameworkStores<TestDbContext>();
            builder.Services.AddJwtEndpoints<TestAppUser>(Jwt);
        });
        var error = Assert.Throws<InvalidOperationException>(() => missing.MapJwtSessionEndpoints<TestAppUser>());
        Assert.Contains("needs an IRefreshTokenStore", error.Message, StringComparison.Ordinal);

        using var custom = Host(builder =>
        {
            builder.Services.AddAuthEndpointsIdentity<TestAppUser>().AddEntityFrameworkStores<TestDbContext>();
            builder.Services.AddJwtEndpoints<TestAppUser>(Jwt).AddRefreshTokenService<NoStoreRefreshTokens>();
        });
        custom.MapJwtSessionEndpoints<TestAppUser>();
    }

    [Fact]
    public void MapEmailCode_WithEfStoresButNoTable_NamesUseEmailCodes()
    {
        using var app = Host(builder => builder.Services.AddAuthEndpoints<TestAppUser>()
            .AddEntityFrameworkStores<IdentityOnlyDbContext>()
            .AddEmailCode());

        var error = Assert.Throws<NotSupportedException>(() => app.MapEmailCodeEndpoints<TestAppUser>());
        Assert.Contains("modelBuilder.UseEmailCodes()", error.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(IdentityOnlyDbContext), error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddRoles_BeforeStores_RegistersTheRoleStore_AfterStores_Throws()
    {
        var services = new ServiceCollection();
        services.AddAuthEndpoints<TestAppUser>().AddRoles<IdentityRole>().AddEntityFrameworkStores<TestDbContext>();
        Assert.Contains(services, d => d.ServiceType == typeof(IRoleStore<IdentityRole>));
        Assert.Contains(services, d => d.ServiceType == typeof(IUserStore<TestAppUser>));

        var late = new ServiceCollection().AddAuthEndpoints<TestAppUser>().AddEntityFrameworkStores<TestDbContext>();
        var error = Assert.Throws<InvalidOperationException>(() => late.AddRoles<IdentityRole>());
        Assert.Contains("Call AddRoles before AddEntityFrameworkStores", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RefreshTokenService_LostRace_RevokesTheFamilyEvenWhenTheRequestIsCancelled()
    {
        var store = new LosingRotationStore();
        var service = new RefreshTokenService(store, TimeProvider.System, Options.Create(new SimpleJwtOptions()));
        var presented = Token("presented", DateTime.UtcNow, sessionId: null);
        using var aborted = new CancellationTokenSource();
        aborted.Cancel();

        Assert.Null(await service.RotateAsync(presented, "stamp", aborted.Token));

        Assert.Equal("family", store.RevokedFamily);
        Assert.False(store.RevokeFamilyToken.IsCancellationRequested);
    }

    private static void Jwt(SimpleJwtOptions jwt)
    {
        jwt.Issuer = "https://issuer.test";
        jwt.Audience = "https://audience.test";
        jwt.SigningOptions.SymmetricKey = new string('k', 64);
    }

    [Fact]
    public void Development_BuildValidation_NamesTheMissingStore()
    {
        // In Development, Build() validates DI before any endpoint is mapped, so the framework's message comes first.
        // It still names the interface; the map-time message above adds the fix when validation is off.
        var error = Assert.Throws<AggregateException>(() => Host(
            builder =>
            {
                builder.Services.AddAuthEndpointsIdentity<TestAppUser>().AddEntityFrameworkStores<TestDbContext>();
                builder.Services.AddEmailCodeEndpoints<TestAppUser>();
            },
            Environments.Development));
        Assert.Contains(nameof(IEmailCodeStore), error.Message, StringComparison.Ordinal);
    }

    private static WebApplication Host(Action<WebApplicationBuilder> configure, string? environment = null)
    {
        // Production skips Build()'s DI validation, so the map-time check is the first to run.
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment ?? Environments.Production });
        builder.WebHost.UseTestServer();
        var name = "StoreInterface_" + Guid.NewGuid().ToString("N");
        builder.Services.AddDbContext<TestDbContext>(options => options.UseInMemoryDatabase(name));
        builder.Services.AddDbContext<IdentityOnlyDbContext>(options => options.UseInMemoryDatabase(name + "_identity"));
        builder.Services.AddSingleton<IEmailSender<TestAppUser>, TestEmailSender>();
        configure(builder);
        return builder.Build();
    }

    public sealed class IdentityOnlyDbContext(DbContextOptions<IdentityOnlyDbContext> options)
        : Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext<TestAppUser>(options);

    private sealed class NoStoreRefreshTokens : IRefreshTokenService
    {
        public Task<RefreshToken?> GetRefreshTokenAsync(string rawToken, CancellationToken cancellationToken = default)
            => Task.FromResult<RefreshToken?>(null);

        public Task RevokeAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<RefreshToken> CreateAsync(string userId, string securityStamp, string? familyId = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<RefreshToken?> RotateAsync(RefreshToken refreshToken, string securityStamp, CancellationToken cancellationToken = default)
            => Task.FromResult<RefreshToken?>(null);

        public bool IsValid(RefreshToken refreshToken) => false;
    }

    private sealed class LosingRotationStore : IRefreshTokenStore
    {
        public string? RevokedFamily { get; private set; }

        public CancellationToken RevokeFamilyToken { get; private set; }

        public Task<RefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken)
            => Task.FromResult<RefreshToken?>(null);

        public Task CreateAsync(RefreshToken token, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<bool> TryRotateAsync(string presentedId, RefreshToken successor, DateTime revokedAt, CancellationToken cancellationToken)
            => Task.FromResult(false);

        public Task RevokeAsync(string id, DateTime revokedAt, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RevokeFamilyAsync(string familyId, DateTime revokedAt, CancellationToken cancellationToken)
        {
            RevokedFamily = familyId;
            RevokeFamilyToken = cancellationToken;
            return Task.CompletedTask;
        }

        public Task<DateTime?> FindFamilyAbsoluteExpiresAtAsync(string familyId, CancellationToken cancellationToken)
            => Task.FromResult<DateTime?>(null);

        public Task SetSessionAsync(string tokenId, string sessionId, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<IReadOnlyList<string>> FindFamilySessionIdsAsync(string familyId, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<string>>([]);

        public Task RevokeSessionsAsync(IReadOnlyCollection<string> sessionIds, DateTime revokedAt, CancellationToken cancellationToken)
            => Task.CompletedTask;
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

    private sealed class RecordingRefreshTokenStore : IRefreshTokenStore
    {
        public List<(string? TokenOnArrival, string Hash)> Received { get; } = [];

        public Task<RefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken)
            => Task.FromResult<RefreshToken?>(null);

        public Task CreateAsync(RefreshToken token, CancellationToken cancellationToken)
        {
            Received.Add((token.Token, token.TokenHash));
            return Task.CompletedTask;
        }

        public Task<bool> TryRotateAsync(string presentedId, RefreshToken successor, DateTime revokedAt, CancellationToken cancellationToken)
        {
            Received.Add((successor.Token, successor.TokenHash));
            return Task.FromResult(true);
        }

        public Task RevokeAsync(string id, DateTime revokedAt, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RevokeFamilyAsync(string familyId, DateTime revokedAt, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<DateTime?> FindFamilyAbsoluteExpiresAtAsync(string familyId, CancellationToken cancellationToken)
            => Task.FromResult<DateTime?>(null);

        public Task SetSessionAsync(string tokenId, string sessionId, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<IReadOnlyList<string>> FindFamilySessionIdsAsync(string familyId, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<string>>([]);

        public Task RevokeSessionsAsync(IReadOnlyCollection<string> sessionIds, DateTime revokedAt, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

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
