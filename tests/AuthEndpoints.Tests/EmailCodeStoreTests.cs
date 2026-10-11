using System.Buffers.Text;
using System.Collections.Concurrent;
using AuthEndpoints.EmailCode;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using EmailCodeEntity = AuthEndpoints.EmailCode.EmailCodeEntry;

namespace AuthEndpoints.Tests;

public class EmailCodeStoreTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task UseEmailCodes_IsOptIn()
    {
        using var optedIn = new SqliteDatabase();
        await using var mapped = optedIn.Open();
        var entity = mapped.Model.FindEntityType(typeof(EmailCodeEntity));
        Assert.NotNull(entity);
        Assert.Equal("AuthEndpointsEmailCodes", entity.GetTableName());
        Assert.Equal("AuthEndpoints", entity.GetSchema());
        var emailIndex = entity.GetIndexes().Single(i =>
            i.Properties.Count == 2
            && i.Properties[0].Name == nameof(EmailCodeEntity.EmailHash)
            && i.Properties[1].Name == nameof(EmailCodeEntity.CreatedAt));
        Assert.False(emailIndex.IsUnique);
        var linkIndex = entity.GetIndexes().Single(i => i.IsUnique && i.Properties.Any(p => p.Name == nameof(EmailCodeEntity.LinkTokenHash)));
        Assert.Null(linkIndex.GetFilter());

        var mappedTables = await SqliteTablesAsync(mapped);
        Assert.Contains(mappedTables, name => name.Contains("AuthEndpointsEmailCodes", StringComparison.Ordinal));

        var plainPath = Path.Combine(Path.GetTempPath(), $"ae-email-code-plain-{Guid.NewGuid():N}.sqlite");
        try
        {
            var plainOptions = new DbContextOptionsBuilder<PlainDbContext>()
                .UseSqlite($"Data Source={plainPath}")
                .Options;
            await using var unmapped = new PlainDbContext(plainOptions);
            unmapped.Database.EnsureCreated();
            Assert.Null(unmapped.Model.FindEntityType(typeof(EmailCodeEntity)));
            var plainTables = await SqliteTablesAsync(unmapped);
            Assert.DoesNotContain(plainTables, name => name.Contains("AuthEndpointsEmailCodes", StringComparison.Ordinal));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(plainPath))
            {
                File.Delete(plainPath);
            }
        }
    }

    [Fact]
    public async Task Issue_StoresHashOnly_AndLookupIsByEmail()
    {
        using var db = new SqliteDatabase();
        await using var context = db.Open();
        var store = NewStore(context);
        EmailCodeIssueResult issued = await store.IssueAsync("A@X.com ", "user-1", "stamp-1");

        EmailCodeEntity row = await context.Set<EmailCodeEntity>().AsNoTracking().SingleAsync();
        Assert.Equal(issued.Id, row.Id);
        Assert.Equal(issued.EmailHash, row.EmailHash);
        Assert.Equal(EmailCodeHasher.HashCode(row.Id, issued.Code), row.CodeHash);
        Assert.NotEqual(issued.Code, row.CodeHash);
        Assert.Equal("user-1", row.UserId);
        Assert.Equal("stamp-1", row.SecurityStamp);
        Assert.Null(row.LinkTokenHash);
        Assert.Null(row.ConsumedAt);
        Assert.Null(row.SupersededAt);
        Assert.Equal(0, row.Attempts);
        Assert.Equal(6, issued.Code.Length);

        EmailCodeEntity? live = await store.FindLiveByEmailAsync("a@x.com");
        Assert.NotNull(live);
        Assert.Equal(issued.Id, live.Id);
        Assert.True(store.CodeMatches(live, issued.Code));
        Assert.False(store.CodeMatches(live, issued.Code == "000000" ? "000001" : "000000"));
        Assert.Null(await store.FindLiveByEmailAsync("other@x.com"));
    }

    [Fact]
    public async Task Issue_WithMagicLink_StoresTokenHashOnly()
    {
        using var db = new SqliteDatabase();
        await using var context = db.Open();
        var options = new EmailCodeOptions
        {
            MagicLink = new EmailCodeMagicLinkOptions { Enabled = true, LinkUri = "/auth/email-link" }
        };
        var store = NewStore(context, options);
        EmailCodeIssueResult issued = await store.IssueAsync("a@x.com", null, null);

        Assert.NotNull(issued.LinkToken);
        byte[] tokenBytes = Base64Url.DecodeFromChars(issued.LinkToken);
        Assert.Equal(32, tokenBytes.Length);

        EmailCodeEntity row = await context.Set<EmailCodeEntity>().AsNoTracking().SingleAsync();
        Assert.Equal(EmailCodeHasher.HashLinkToken(issued.LinkToken), row.LinkTokenHash);
        Assert.NotEqual(issued.LinkToken, row.LinkTokenHash);
        Assert.Null(row.UserId);
    }

    [Fact]
    public async Task Resend_SupersedesPreviousRowInOneTransaction()
    {
        using var db = new SqliteDatabase();
        await using var context = db.Open();
        var store = NewStore(context);
        EmailCodeIssueResult first = await store.IssueAsync("a@x.com", "user", "stamp");
        EmailCodeIssueResult second = await store.IssueAsync("a@x.com", "user", "stamp");

        List<EmailCodeEntity> rows = await context.Set<EmailCodeEntity>().AsNoTracking().OrderBy(e => e.CreatedAt).ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.NotNull(rows[0].SupersededAt);
        Assert.Null(rows[1].SupersededAt);
        Assert.Equal(second.Id, rows[1].Id);

        EmailCodeEntity? live = await store.FindLiveByEmailAsync("a@x.com");
        Assert.NotNull(live);
        Assert.Equal(second.Id, live.Id);
        Assert.True(store.CodeMatches(live, second.Code));
        Assert.False(store.CodeMatches(live, first.Code));

        EmailCodeEntity old = await context.Set<EmailCodeEntity>().SingleAsync(e => e.Id == first.Id);
        Assert.False(await store.TryConsumeAsync(old));
        Assert.Null((await context.Set<EmailCodeEntity>().AsNoTracking().SingleAsync(e => e.Id == first.Id)).ConsumedAt);
    }

    [Fact]
    public async Task Resend_RollsBackSupersedeWhenInsertFails()
    {
        using var db = new SqliteDatabase();
        string firstId;
        await using (var seed = db.Open())
        {
            EmailCodeIssueResult first = await NewStore(seed).IssueAsync("a@x.com", "user", "stamp");
            firstId = first.Id;
        }

        await using (var failing = db.Open(new ThrowOnSaveChangesInterceptor()))
        {
            var store = NewStore(failing);
            Exception ex = await Assert.ThrowsAnyAsync<Exception>(() => store.IssueAsync("a@x.com", "user", "stamp"));
            Assert.Contains("fail save", ex.ToString(), StringComparison.Ordinal);
        }

        await using var check = db.Open();
        List<EmailCodeEntity> rows = await check.Set<EmailCodeEntity>().AsNoTracking().ToListAsync();
        EmailCodeEntity only = Assert.Single(rows);
        Assert.Equal(firstId, only.Id);
        Assert.Null(only.SupersededAt);
        Assert.Null(only.ConsumedAt);
    }

    [Fact]
    public async Task Attempts_StopAtMax_AndThenConsumeFails()
    {
        using var db = new SqliteDatabase();
        await using var context = db.Open();
        var options = new EmailCodeOptions { MaxAttempts = 5 };
        var store = NewStore(context, options);
        EmailCodeIssueResult issued = await store.IssueAsync("a@x.com", "user", "stamp");

        for (var i = 0; i < 5; i++)
        {
            EmailCodeEntity current = await context.Set<EmailCodeEntity>().SingleAsync(e => e.Id == issued.Id);
            Assert.True(await store.TryReserveAttemptAsync(current));
        }

        EmailCodeEntity exhausted = await context.Set<EmailCodeEntity>().SingleAsync(e => e.Id == issued.Id);
        Assert.Equal(5, exhausted.Attempts);
        Assert.False(await store.TryReserveAttemptAsync(exhausted));
        Assert.Equal(5, (await context.Set<EmailCodeEntity>().AsNoTracking().SingleAsync(e => e.Id == issued.Id)).Attempts);
        Assert.True(EmailCodeHasher.CodeMatches(issued.Id, issued.Code, exhausted.CodeHash));
        Assert.False(await store.TryConsumeAsync(exhausted));
        Assert.Null(await store.FindLiveByEmailAsync("a@x.com"));
        Assert.Null((await context.Set<EmailCodeEntity>().AsNoTracking().SingleAsync(e => e.Id == issued.Id)).ConsumedAt);
    }

    [Fact]
    public async Task Consume_IsSingleUse_AndRejectsExpiredRow()
    {
        using var db = new SqliteDatabase();
        await using var context = db.Open();
        var clock = new MutableTimeProvider(Start);
        var store = NewStore(context, time: clock);
        EmailCodeIssueResult issued = await store.IssueAsync("a@x.com", "user", "stamp");

        EmailCodeEntity row = await context.Set<EmailCodeEntity>().SingleAsync(e => e.Id == issued.Id);
        Assert.True(await store.TryConsumeAsync(row));
        Assert.NotNull(row.ConsumedAt);

        EmailCodeEntity again = await context.Set<EmailCodeEntity>().SingleAsync(e => e.Id == issued.Id);
        Assert.False(await store.TryConsumeAsync(again));
        Assert.Null(await store.FindLiveByEmailAsync("a@x.com"));

        clock.Advance(TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(1));
        EmailCodeIssueResult later = await store.IssueAsync("b@x.com", "user", "stamp");
        EmailCodeEntity expired = await context.Set<EmailCodeEntity>().SingleAsync(e => e.Id == later.Id);
        clock.Advance(TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(1));
        Assert.False(await store.TryConsumeAsync(expired));
        Assert.Null(await store.FindLiveByEmailAsync("b@x.com"));
        Assert.Null((await context.Set<EmailCodeEntity>().AsNoTracking().SingleAsync(e => e.Id == later.Id)).ConsumedAt);
    }

    [Fact]
    public async Task ParallelConsume_OnlyOneSucceeds()
    {
        using var db = new SqliteDatabase();
        string id;
        await using (var seed = db.Open())
        {
            EmailCodeIssueResult issued = await NewStore(seed).IssueAsync("a@x.com", "user", "stamp");
            id = issued.Id;
        }

        await using var dbA = db.Open();
        await using var dbB = db.Open();
        EmailCodeEntity rowA = await dbA.Set<EmailCodeEntity>().SingleAsync(e => e.Id == id);
        EmailCodeEntity rowB = await dbB.Set<EmailCodeEntity>().SingleAsync(e => e.Id == id);
        var storeA = NewStore(dbA);
        var storeB = NewStore(dbB);
        var barrier = new Barrier(2);
        var results = new ConcurrentBag<(bool Won, Exception? Error)>();

        async Task Consume(EmailCodeStore<MappedEmailCodeDbContext> store, EmailCodeEntity row)
        {
            barrier.SignalAndWait(TimeSpan.FromSeconds(10));
            try
            {
                results.Add((await store.TryConsumeAsync(row), null));
            }
            catch (Exception ex)
            {
                results.Add((false, ex));
            }
        }

        await Task.WhenAll(Consume(storeA, rowA), Consume(storeB, rowB));

        Assert.Equal(2, results.Count);
        Assert.All(results, result => Assert.Null(result.Error));
        Assert.Equal(1, results.Count(result => result.Won));
        Assert.Equal(1, results.Count(result => !result.Won));

        await using var check = db.Open();
        EmailCodeEntity saved = await check.Set<EmailCodeEntity>().AsNoTracking().SingleAsync(e => e.Id == id);
        Assert.NotNull(saved.ConsumedAt);
    }

    [Fact]
    public async Task Issue_DeletesRowsExpiredMoreThan24HoursAgo()
    {
        using var db = new SqliteDatabase();
        await using var context = db.Open();
        var clock = new MutableTimeProvider(Start);
        var store = NewStore(context, time: clock);

        EmailCodeIssueResult stale = await store.IssueAsync("a@x.com", null, null);
        EmailCodeIssueResult other = await store.IssueAsync("b@x.com", null, null);
        clock.Advance(TimeSpan.FromHours(24) + TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(1));
        EmailCodeIssueResult fresh = await store.IssueAsync("a@x.com", null, null);

        List<string> ids = await context.Set<EmailCodeEntity>().AsNoTracking().Select(e => e.Id).ToListAsync();
        Assert.DoesNotContain(stale.Id, ids);
        Assert.Contains(other.Id, ids);
        Assert.Contains(fresh.Id, ids);

        EmailCodeIssueResult recent = await store.IssueAsync("c@x.com", null, null);
        clock.Advance(TimeSpan.FromHours(23));
        EmailCodeIssueResult resent = await store.IssueAsync("c@x.com", null, null);
        ids = await context.Set<EmailCodeEntity>().AsNoTracking().Select(e => e.Id).ToListAsync();
        Assert.Contains(recent.Id, ids);
        Assert.Contains(resent.Id, ids);
        Assert.Contains(other.Id, ids);

        EmailCodeIssueResult replaced = await store.IssueAsync("b@x.com", null, null);
        ids = await context.Set<EmailCodeEntity>().AsNoTracking().Select(e => e.Id).ToListAsync();
        Assert.DoesNotContain(other.Id, ids);
        Assert.Contains(replaced.Id, ids);
        Assert.Contains(recent.Id, ids);
    }

    [Fact]
    public async Task CooldownAndCap_AreCountedFromRows()
    {
        using var db = new SqliteDatabase();
        await using var context = db.Open();
        var clock = new MutableTimeProvider(Start);
        var options = new EmailCodeOptions
        {
            ResendCooldown = TimeSpan.FromSeconds(60),
            MaxSendsPerEmail = 2,
            SendWindow = TimeSpan.FromHours(1)
        };
        var store = NewStore(context, options, clock);

        Assert.False(await store.IsWithinResendCooldownAsync("a@x.com"));
        Assert.False(await store.HasReachedSendCapAsync("a@x.com"));

        await store.IssueAsync("a@x.com", null, null);
        Assert.True(await store.IsWithinResendCooldownAsync("A@X.com "));
        Assert.False(await store.IsWithinResendCooldownAsync("b@x.com"));
        Assert.False(await store.HasReachedSendCapAsync("a@x.com"));

        clock.Advance(TimeSpan.FromSeconds(60));
        Assert.False(await store.IsWithinResendCooldownAsync("a@x.com"));

        await store.IssueAsync("a@x.com", null, null);
        Assert.True(await store.HasReachedSendCapAsync("a@x.com"));
        Assert.False(await store.HasReachedSendCapAsync("b@x.com"));

        clock.Advance(TimeSpan.FromHours(1));
        Assert.False(await store.HasReachedSendCapAsync("a@x.com"));
        Assert.False(await store.IsWithinResendCooldownAsync("a@x.com"));
    }

    [Fact]
    public async Task Issue_UsesTheLookupNormalizer()
    {
        using var db = new SqliteDatabase();
        await using var context = db.Open();
        var normalizer = new MarkerNormalizer();
        var store = NewStore(context, normalizer: normalizer);
        EmailCodeIssueResult issued = await store.IssueAsync("A@X.com ", null, null);

        Assert.Equal(EmailCodeHasher.HashEmail("mark:A@X.com"), issued.EmailHash);
        Assert.NotNull(await store.FindLiveByEmailAsync("A@X.com "));
        Assert.Null(await store.FindLiveByEmailAsync("other@x.com"));
    }

    [Fact]
    public async Task ReservedLastAttempt_CanBeConsumed_UnreservedMaxCannot()
    {
        using var db = new SqliteDatabase();
        await using var context = db.Open();
        var store = NewStore(context, new EmailCodeOptions { MaxAttempts = 1, ResendCooldown = TimeSpan.Zero });
        EmailCodeIssueResult issued = await store.IssueAsync("a@x.com", "user", "stamp");

        EmailCodeEntity row = await context.Set<EmailCodeEntity>().SingleAsync(e => e.Id == issued.Id);
        Assert.True(await store.TryReserveAttemptAsync(row));
        EmailCodeEntity reserved = await context.Set<EmailCodeEntity>().SingleAsync(e => e.Id == issued.Id);
        Assert.Equal(1, reserved.Attempts);
        Assert.False(await store.TryConsumeAsync(reserved));
        Assert.True(await store.TryConsumeReservedAsync(reserved));
        Assert.NotNull((await context.Set<EmailCodeEntity>().AsNoTracking().SingleAsync(e => e.Id == issued.Id)).ConsumedAt);
    }

    [Fact]
    public async Task ParallelIssue_WithinCooldown_InsertsOneRow()
    {
        using var db = new SqliteDatabase();
        var options = new EmailCodeOptions { ResendCooldown = TimeSpan.FromSeconds(60) };
        var clock = new MutableTimeProvider(Start);
        await using (var wal = db.Open())
        {
            await wal.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");
        }

        async Task<EmailCodeIssueResult> Issue()
        {
            await using var context = db.Open();
            var store = NewStore(context, options, clock);
            return await store.IssueAsync("a@x.com", "user", "stamp");
        }

        EmailCodeIssueResult[] results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Issue()));
        Assert.Equal(1, results.Count(result => !result.Suppressed));
        Assert.Equal(7, results.Count(result => result.Suppressed));

        await using var check = db.Open();
        Assert.Equal(1, await check.Set<EmailCodeEntity>().CountAsync());
    }

    private static EmailCodeStore<MappedEmailCodeDbContext> NewStore(
        MappedEmailCodeDbContext context,
        EmailCodeOptions? options = null,
        TimeProvider? time = null,
        ILookupNormalizer? normalizer = null)
    {
        return new EmailCodeStore<MappedEmailCodeDbContext>(
            context,
            time ?? TimeProvider.System,
            options ?? new EmailCodeOptions { ResendCooldown = TimeSpan.Zero },
            normalizer ?? new UpperInvariantLookupNormalizer());
    }

    private static async Task<List<string>> SqliteTablesAsync(DbContext context)
    {
        var connection = context.Database.GetDbConnection();
        if (connection.State != System.Data.ConnectionState.Open)
        {
            await connection.OpenAsync();
        }

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table'";
        var names = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            names.Add(reader.GetString(0));
        }

        return names;
    }

    private sealed class MarkerNormalizer : ILookupNormalizer
    {
        public string? NormalizeEmail(string? email) => email is null ? null : "mark:" + email;

        public string? NormalizeName(string? name) => name;
    }

    private sealed class MutableTimeProvider : TimeProvider
    {
        private DateTimeOffset _utc;

        public MutableTimeProvider(DateTimeOffset utc)
        {
            _utc = utc;
        }

        public override DateTimeOffset GetUtcNow() => _utc;

        public void Advance(TimeSpan by) => _utc = _utc.Add(by);
    }

    private sealed class ThrowOnSaveChangesInterceptor : SaveChangesInterceptor
    {
        public override InterceptionResult<int> SavingChanges(
            DbContextEventData eventData,
            InterceptionResult<int> result)
        {
            throw new InvalidOperationException("fail save");
        }

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("fail save");
        }
    }

    private sealed class SqliteDatabase : IDisposable
    {
        private readonly string _path = Path.Combine(Path.GetTempPath(), $"ae-email-code-{Guid.NewGuid():N}.sqlite");

        public MappedEmailCodeDbContext Open(SaveChangesInterceptor? interceptor = null)
        {
            var builder = new DbContextOptionsBuilder<MappedEmailCodeDbContext>()
                .UseSqlite($"Data Source={_path};Default Timeout=30");
            if (interceptor is not null)
            {
                builder.AddInterceptors(interceptor);
            }

            var context = new MappedEmailCodeDbContext(builder.Options);
            context.Database.EnsureCreated();
            return context;
        }

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            TryDelete(_path);
            TryDelete(_path + "-wal");
            TryDelete(_path + "-shm");
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (IOException)
            {
            }
        }
    }

    private sealed class MappedEmailCodeDbContext : DbContext
    {
        public MappedEmailCodeDbContext(DbContextOptions<MappedEmailCodeDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.UseEmailCodes();
        }
    }

    private sealed class PlainDbContext : DbContext
    {
        public PlainDbContext(DbContextOptions<PlainDbContext> options)
            : base(options)
        {
        }
    }
}
