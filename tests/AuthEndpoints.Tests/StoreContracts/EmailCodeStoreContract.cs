using AuthEndpoints.EmailCode;

namespace AuthEndpoints.Tests.StoreContracts;

/// <summary>
/// What every <see cref="IEmailCodeStore"/> must do, from its XML docs. Run against the EF Core store and the in-memory
/// one; a custom store can copy this class and implement <see cref="NewStoreAsync"/>.
/// </summary>
public abstract class EmailCodeStoreContract : IAsyncLifetime
{
    protected static readonly DateTime Now = new(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc);
    private static readonly EmailCodeLiveness Live = new(Now, MaxAttempts: 3);

    /// <summary>A store over this test's data. Each call may return a new instance, as a new request would get.</summary>
    protected abstract Task<IEmailCodeStore> NewStoreAsync();

    public virtual Task InitializeAsync() => Task.CompletedTask;

    public virtual Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Issue_InsertsAndFinds_ByHashAndPurposeOnly()
    {
        var store = await NewStoreAsync();
        var entry = Entry("a");
        Assert.Equal(EmailCodeIssueStatus.Issued, await store.IssueAsync(entry, Rules(), default));

        Assert.Equal(entry.Id, (await store.FindLiveByEmailAsync("a", EmailCodeRowPurpose.SignIn, null, Live, default))?.Id);
        Assert.Null(await store.FindLiveByEmailAsync("b", EmailCodeRowPurpose.SignIn, null, Live, default));
        Assert.Null(await store.FindLiveByEmailAsync("a", EmailCodeRowPurpose.ReAuth, null, Live, default));
        Assert.Null(await store.FindLiveByEmailAsync("a", EmailCodeRowPurpose.SignIn, "someone-else", Live, default));
        Assert.NotNull(await store.FindLiveByEmailAsync("a", EmailCodeRowPurpose.SignIn, "user", Live, default));
    }

    [Fact]
    public async Task Issue_WithinCooldown_StoresNothing()
    {
        var store = await NewStoreAsync();
        await store.IssueAsync(Entry("a", createdAt: Now.AddSeconds(-30)), Rules(), default);

        var second = Entry("a");
        Assert.Equal(EmailCodeIssueStatus.Cooldown, await store.IssueAsync(second, Rules(cooldownSince: Now.AddSeconds(-60)), default));
        Assert.Equal(1, await store.CountIssuedSinceAsync("a", EmailCodeRowPurpose.SignIn, Now.AddDays(-1), default));
        Assert.NotEqual(second.Id, (await store.FindLiveByEmailAsync("a", EmailCodeRowPurpose.SignIn, null, Live, default))?.Id);
    }

    [Fact]
    public async Task Issue_SupersedesLiveRows_AndDeletesLongExpiredOnes()
    {
        var store = await NewStoreAsync();
        var expired = Entry("a", createdAt: Now.AddDays(-3), expiresAt: Now.AddDays(-2));
        var older = Entry("a", createdAt: Now.AddMinutes(-5));
        await store.IssueAsync(expired, Rules(deleteExpiredBefore: Now.AddDays(-7)), default);
        await store.IssueAsync(older, Rules(deleteExpiredBefore: Now.AddDays(-7)), default);
        Assert.Equal(2, await store.CountIssuedSinceAsync("a", EmailCodeRowPurpose.SignIn, Now.AddDays(-7), default));

        var newer = Entry("a");
        await store.IssueAsync(newer, Rules(deleteExpiredBefore: Now.AddDays(-1)), default);

        Assert.Equal(newer.Id, (await store.FindLiveByEmailAsync("a", EmailCodeRowPurpose.SignIn, null, Live, default))?.Id);
        Assert.False(await store.TryConsumeAsync(older.Id, Live, attemptReserved: false, default));
        Assert.Equal(2, await store.CountIssuedSinceAsync("a", EmailCodeRowPurpose.SignIn, Now.AddDays(-7), default));
    }

    [Fact]
    public async Task FindLiveByEmail_IgnoresExpiredConsumedAndExhaustedRows()
    {
        var store = await NewStoreAsync();
        var expired = Entry("expired", expiresAt: Now);
        await store.IssueAsync(expired, Rules(), default);
        Assert.Null(await store.FindLiveByEmailAsync("expired", EmailCodeRowPurpose.SignIn, null, Live, default));

        var consumed = Entry("consumed");
        await store.IssueAsync(consumed, Rules(), default);
        Assert.True(await store.TryConsumeAsync(consumed.Id, Live, attemptReserved: false, default));
        Assert.Null(await store.FindLiveByEmailAsync("consumed", EmailCodeRowPurpose.SignIn, null, Live, default));

        var exhausted = Entry("exhausted");
        await store.IssueAsync(exhausted, Rules(), default);
        for (var i = 0; i < Live.MaxAttempts; i++)
        {
            Assert.True(await store.TryReserveAttemptAsync(exhausted.Id, Live, default));
        }

        Assert.False(await store.TryReserveAttemptAsync(exhausted.Id, Live, default));
        Assert.Null(await store.FindLiveByEmailAsync("exhausted", EmailCodeRowPurpose.SignIn, null, Live, default));
    }

    [Fact]
    public async Task FindLiveByLinkToken_FindsOnlyLiveSignInRows()
    {
        var store = await NewStoreAsync();
        var signIn = Entry("a", linkTokenHash: "link-1");
        var reAuth = Entry("b", purpose: EmailCodeRowPurpose.ReAuth, linkTokenHash: "link-2");
        await store.IssueAsync(signIn, Rules(), default);
        await store.IssueAsync(reAuth, Rules(), default);

        Assert.Equal(signIn.Id, (await store.FindLiveByLinkTokenAsync("link-1", Live, default))?.Id);
        Assert.Null(await store.FindLiveByLinkTokenAsync("link-2", Live, default));
        Assert.Null(await store.FindLiveByLinkTokenAsync("link-1", new EmailCodeLiveness(Now.AddDays(1), 3), default));
    }

    [Fact]
    public async Task Consume_WithAReservedLastAttempt_IsAllowed_WithoutItIsNot()
    {
        var store = await NewStoreAsync();
        var entry = Entry("a");
        await store.IssueAsync(entry, Rules(), default);
        for (var i = 0; i < Live.MaxAttempts; i++)
        {
            await store.TryReserveAttemptAsync(entry.Id, Live, default);
        }

        Assert.False(await store.TryConsumeAsync(entry.Id, Live, attemptReserved: false, default));
        Assert.True(await store.TryConsumeAsync(entry.Id, Live, attemptReserved: true, default));
        Assert.False(await store.TryConsumeAsync(entry.Id, Live, attemptReserved: true, default));
    }

    [Fact]
    public async Task ReleaseAndUnconsume_UndoOnlyWhatHappened()
    {
        var store = await NewStoreAsync();
        var entry = Entry("a");
        await store.IssueAsync(entry, Rules(), default);

        Assert.False(await store.TryReleaseAttemptAsync(entry.Id, default));
        Assert.False(await store.TryUnconsumeAsync(entry.Id, default));
        Assert.True(await store.TryReserveAttemptAsync(entry.Id, Live, default));
        Assert.True(await store.TryReleaseAttemptAsync(entry.Id, default));
        Assert.Equal(0, (await store.FindLiveByEmailAsync("a", EmailCodeRowPurpose.SignIn, null, Live, default))!.Attempts);

        Assert.True(await store.TryConsumeAsync(entry.Id, Live, attemptReserved: false, default));
        Assert.True(await store.TryUnconsumeAsync(entry.Id, default));
        Assert.False(await store.TryUnconsumeAsync(entry.Id, default));
        Assert.NotNull(await store.FindLiveByEmailAsync("a", EmailCodeRowPurpose.SignIn, null, Live, default));
    }

    [Fact]
    public async Task ConcurrentConsumes_OfOneRow_ExactlyOneWins()
    {
        var entry = Entry("a");
        await (await NewStoreAsync()).IssueAsync(entry, Rules(), default);
        var stores = new List<IEmailCodeStore>();
        for (var i = 0; i < 12; i++)
        {
            stores.Add(await NewStoreAsync());
        }

        var results = await Task.WhenAll(stores.Select(store =>
            Task.Run(() => store.TryConsumeAsync(entry.Id, Live, attemptReserved: false, default))));

        Assert.Equal(1, results.Count(won => won));
    }

    [Fact]
    public async Task ConcurrentReservations_NeverExceedMaxAttempts()
    {
        var entry = Entry("a");
        await (await NewStoreAsync()).IssueAsync(entry, Rules(), default);
        var stores = new List<IEmailCodeStore>();
        for (var i = 0; i < 12; i++)
        {
            stores.Add(await NewStoreAsync());
        }

        var results = await Task.WhenAll(stores.Select(store =>
            Task.Run(() => store.TryReserveAttemptAsync(entry.Id, Live, default))));

        Assert.Equal(Live.MaxAttempts, results.Count(won => won));
    }

    [Fact]
    public async Task ConcurrentIssues_WithinCooldown_IssueAtMostOneLiveRow()
    {
        var stores = new List<IEmailCodeStore>();
        for (var i = 0; i < 8; i++)
        {
            stores.Add(await NewStoreAsync());
        }

        var results = await Task.WhenAll(stores.Select(store =>
            Task.Run(() => store.IssueAsync(Entry("a"), Rules(cooldownSince: Now.AddSeconds(-60)), default))));

        Assert.Equal(1, results.Count(status => status == EmailCodeIssueStatus.Issued));
        Assert.All(results, status => Assert.NotEqual(EmailCodeIssueStatus.Conflict, status));
        Assert.Equal(1, await (await NewStoreAsync()).CountIssuedSinceAsync("a", EmailCodeRowPurpose.SignIn, Now.AddDays(-1), default));
    }

    protected static EmailCodeEntry Entry(
        string emailHash,
        EmailCodeRowPurpose purpose = EmailCodeRowPurpose.SignIn,
        DateTime? createdAt = null,
        DateTime? expiresAt = null,
        string? linkTokenHash = null) => new()
        {
            Id = Guid.NewGuid().ToString(),
            EmailHash = emailHash,
            Purpose = purpose,
            UserId = "user",
            CodeHash = "code-hash",
            LinkTokenHash = linkTokenHash,
            SecurityStamp = "stamp",
            CreatedAt = createdAt ?? Now,
            ExpiresAt = expiresAt ?? Now.AddMinutes(10),
        };

    private static EmailCodeIssueRules Rules(DateTime? cooldownSince = null, DateTime? deleteExpiredBefore = null) => new()
    {
        Liveness = Live,
        CooldownSince = cooldownSince,
        DeleteExpiredBefore = deleteExpiredBefore ?? Now.AddHours(-24),
    };
}
