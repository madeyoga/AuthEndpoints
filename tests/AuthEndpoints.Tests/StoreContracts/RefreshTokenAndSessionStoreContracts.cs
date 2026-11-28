using AuthEndpoints.Jwt;
using AuthEndpoints.Sessions;

namespace AuthEndpoints.Tests.StoreContracts;

/// <summary>What every <see cref="IRefreshTokenStore"/> must do, from its XML docs.</summary>
public abstract class RefreshTokenStoreContract : IAsyncLifetime
{
    protected static readonly DateTime Now = new(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>A store over this test's data. Each call may return a new instance, as a new request would get.</summary>
    protected abstract Task<IRefreshTokenStore> NewStoreAsync();

    public virtual Task InitializeAsync() => Task.CompletedTask;

    public virtual Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task CreateAndFind_ByHash()
    {
        var store = await NewStoreAsync();
        var token = Token("hash-1", "family");
        await store.CreateAsync(token, default);

        var found = await store.FindByHashAsync("hash-1", default);
        Assert.Equal(token.Id, found?.Id);
        Assert.Equal("family", found?.FamilyId);
        Assert.Null(await store.FindByHashAsync("missing", default));
        Assert.Equal(Now.AddDays(30), await store.FindFamilyAbsoluteExpiresAtAsync("family", default));
        Assert.Null(await store.FindFamilyAbsoluteExpiresAtAsync("other", default));
    }

    [Fact]
    public async Task Rotate_RevokesThePresentedToken_AndStoresTheSuccessor_Once()
    {
        var store = await NewStoreAsync();
        var presented = Token("presented", "family");
        await store.CreateAsync(presented, default);

        var successor = Token("successor", "family");
        Assert.True(await store.TryRotateAsync(presented.Id, successor, Now, default));
        Assert.False(await store.TryRotateAsync(presented.Id, Token("late", "family"), Now, default));

        var revoked = (await store.FindByHashAsync("presented", default))!;
        Assert.NotNull(revoked.RevokedAt);
        Assert.Equal(successor.Id, revoked.ReplacedByTokenId);
        Assert.NotNull(await store.FindByHashAsync("successor", default));
        Assert.Null(await store.FindByHashAsync("late", default));
    }

    [Fact]
    public async Task ConcurrentRotations_OfOneToken_ExactlyOneSucceeds()
    {
        var presented = Token("presented", "family");
        await (await NewStoreAsync()).CreateAsync(presented, default);
        var attempts = new List<(IRefreshTokenStore Store, RefreshToken Successor)>();
        for (var i = 0; i < 10; i++)
        {
            attempts.Add((await NewStoreAsync(), Token($"successor-{i}", "family")));
        }

        var results = await Task.WhenAll(attempts.Select(attempt =>
            Task.Run(() => attempt.Store.TryRotateAsync(presented.Id, attempt.Successor, Now, default))));

        Assert.Equal(1, results.Count(won => won));
        var check = await NewStoreAsync();
        var stored = 0;
        foreach (var (_, successor) in attempts)
        {
            stored += await check.FindByHashAsync(successor.TokenHash, default) is null ? 0 : 1;
        }

        Assert.Equal(1, stored);
    }

    [Fact]
    public async Task Revokes_SetRevokedAt_OnlyWhereItIsUnset()
    {
        var store = await NewStoreAsync();
        var first = Token("first", "family");
        var second = Token("second", "family");
        var other = Token("other", "other-family");
        await store.CreateAsync(first, default);
        await store.CreateAsync(second, default);
        await store.CreateAsync(other, default);

        await store.RevokeAsync(first.Id, Now, default);
        await store.RevokeFamilyAsync("family", Now.AddMinutes(5), default);
        await store.RevokeAsync(first.Id, Now.AddMinutes(10), default);

        Assert.Equal(Now, (await store.FindByHashAsync("first", default))!.RevokedAt);
        Assert.Equal(Now.AddMinutes(5), (await store.FindByHashAsync("second", default))!.RevokedAt);
        Assert.Null((await store.FindByHashAsync("other", default))!.RevokedAt);
    }

    [Fact]
    public async Task Sessions_LinkTokens_AndRevokeBySession()
    {
        var store = await NewStoreAsync();
        var first = Token("first", "family");
        var second = Token("second", "family");
        var other = Token("other", "other-family");
        await store.CreateAsync(first, default);
        await store.CreateAsync(second, default);
        await store.CreateAsync(other, default);

        await store.SetSessionAsync(first.Id, "session-1", default);
        await store.SetSessionAsync(second.Id, "session-1", default);
        await store.SetSessionAsync(other.Id, "session-2", default);

        Assert.Equal(["session-1"], await store.FindFamilySessionIdsAsync("family", default));
        await store.RevokeSessionsAsync(["session-1"], Now, default);
        Assert.NotNull((await store.FindByHashAsync("first", default))!.RevokedAt);
        Assert.NotNull((await store.FindByHashAsync("second", default))!.RevokedAt);
        Assert.Null((await store.FindByHashAsync("other", default))!.RevokedAt);
    }

    protected static RefreshToken Token(string hash, string familyId) => new()
    {
        TokenHash = hash,
        FamilyId = familyId,
        SecurityStamp = "stamp",
        UserId = "user",
        ExpiresAt = Now.AddDays(14),
        AbsoluteExpiresAt = Now.AddDays(30),
    };
}

/// <summary>What every <see cref="IActiveSessionStore"/> must do, from its XML docs.</summary>
public abstract class ActiveSessionStoreContract : IAsyncLifetime
{
    protected static readonly DateTime Now = new(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>A store over this test's data. Each call may return a new instance, as a new request would get.</summary>
    protected abstract Task<IActiveSessionStore> NewStoreAsync();

    public virtual Task InitializeAsync() => Task.CompletedTask;

    public virtual Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Create_KeepsTheFirstOfTwoWithOneId()
    {
        var store = await NewStoreAsync();
        Assert.True(await store.TryCreateAsync(Session("s1", "user", stamp: "first"), default));
        Assert.False(await store.TryCreateAsync(Session("s1", "user", stamp: "second"), default));
        Assert.Equal("first", (await store.FindAsync("s1", default))?.SecurityStamp);
    }

    [Fact]
    public async Task ConcurrentCreates_OfOneId_ExactlyOneInserts()
    {
        var stores = new List<IActiveSessionStore>();
        for (var i = 0; i < 8; i++)
        {
            stores.Add(await NewStoreAsync());
        }

        var results = await Task.WhenAll(stores.Select((store, i) =>
            Task.Run(() => store.TryCreateAsync(Session("race", "user", stamp: $"stamp-{i}"), default))));

        Assert.Equal(1, results.Count(created => created));
    }

    [Fact]
    public async Task TouchAndStamp_ChangeOnlyUnrevokedSessions()
    {
        var store = await NewStoreAsync();
        await store.TryCreateAsync(Session("live", "user"), default);
        await store.TryCreateAsync(Session("ended", "user"), default);
        await store.RevokeAsync(["ended"], Now, default);

        await store.TouchAsync("live", Now.AddMinutes(5), Now.AddDays(2), default);
        await store.UpdateStampAsync("live", "new-stamp", Now.AddMinutes(6), null, default);
        await store.TouchAsync("ended", Now.AddMinutes(5), null, default);

        var live = (await store.FindAsync("live", default))!;
        Assert.Equal(Now.AddMinutes(6), live.LastSeenAt);
        Assert.Equal(Now.AddDays(2), live.ExpiresAt);
        Assert.Equal("new-stamp", live.SecurityStamp);
        Assert.Equal(Now, (await store.FindAsync("ended", default))!.LastSeenAt);
    }

    [Fact]
    public async Task Lists_SeparateActive_FromUnrevoked()
    {
        var store = await NewStoreAsync();
        await store.TryCreateAsync(Session("active", "user"), default);
        await store.TryCreateAsync(Session("expired", "user", expiresAt: Now), default);
        await store.TryCreateAsync(Session("revoked", "user"), default);
        await store.TryCreateAsync(Session("someone-else", "other"), default);
        await store.RevokeAsync(["revoked"], Now, default);

        Assert.Equal(["active"], (await store.ListActiveAsync("user", Now, default)).Select(s => s.Id));
        Assert.Equal(["active", "expired"], (await store.ListUnrevokedIdsAsync("user", default)).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task DeleteEnded_RemovesRevokedAndExpiredOnly()
    {
        var store = await NewStoreAsync();
        await store.TryCreateAsync(Session("active", "user"), default);
        await store.TryCreateAsync(Session("expired", "user", expiresAt: Now), default);
        await store.TryCreateAsync(Session("revoked", "user"), default);
        await store.RevokeAsync(["revoked"], Now, default);

        Assert.Equal(2, await store.DeleteEndedAsync(Now, default));
        Assert.NotNull(await store.FindAsync("active", default));
        Assert.Null(await store.FindAsync("expired", default));
        Assert.Null(await store.FindAsync("revoked", default));
    }

    protected static ActiveSession Session(string id, string userId, string stamp = "stamp", DateTime? expiresAt = null) => new()
    {
        Id = id,
        UserId = userId,
        UserAgent = "agent",
        SecurityStamp = stamp,
        CreatedAt = Now,
        LastSeenAt = Now,
        ExpiresAt = expiresAt ?? Now.AddDays(1),
    };
}
