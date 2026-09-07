using System.Collections.Concurrent;
using System.Net;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Tests;

public class RefreshRotationConcurrencyTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public RefreshRotationConcurrencyTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Service_TwoDbContexts_RotateSameToken_OnlyOneLiveSuccessor()
    {
        var email = $"cas-svc-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email);

        string familyId;
        RefreshToken parent;
        string stamp;

        using (var seedScope = _factory.Services.CreateScope())
        {
            var userManager = seedScope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var tracked = await userManager.FindByIdAsync(user.Id);
            Assert.NotNull(tracked);
            stamp = await userManager.GetSecurityStampAsync(tracked);

            var svc = seedScope.ServiceProvider.GetRequiredService<IRefreshTokenService>();
            parent = await svc.CreateAsync(user.Id, stamp);
            familyId = parent.FamilyId;
        }

        using var scopeA = _factory.Services.CreateScope();
        using var scopeB = _factory.Services.CreateScope();
        var dbA = scopeA.ServiceProvider.GetRequiredService<TestDbContext>();
        var dbB = scopeB.ServiceProvider.GetRequiredService<TestDbContext>();
        var tokenA = await dbA.Set<RefreshToken>().SingleAsync(t => t.Id == parent.Id);
        var tokenB = await dbB.Set<RefreshToken>().SingleAsync(t => t.Id == parent.Id);
        var svcA = scopeA.ServiceProvider.GetRequiredService<IRefreshTokenService>();
        var svcB = scopeB.ServiceProvider.GetRequiredService<IRefreshTokenService>();

        var barrier = new Barrier(2);
        var results = new ConcurrentBag<(string Scope, string? SuccessorId)>();

        async Task Rotate(string label, IRefreshTokenService svc, RefreshToken token)
        {
            barrier.SignalAndWait(TimeSpan.FromSeconds(10));
            var successor = await svc.RotateAsync(token, stamp);
            results.Add((label, successor?.Id));
        }

        await Task.WhenAll(Rotate("A", svcA, tokenA), Rotate("B", svcB, tokenB));

        Assert.Equal(2, results.Count);
        var wins = results.Where(r => r.SuccessorId is not null).ToList();
        var losses = results.Where(r => r.SuccessorId is null).ToList();
        Assert.Single(wins);
        Assert.Single(losses);

        using var checkScope = _factory.Services.CreateScope();
        var checkDb = checkScope.ServiceProvider.GetRequiredService<TestDbContext>();
        var family = await checkDb.Set<RefreshToken>()
            .Where(t => t.FamilyId == familyId)
            .ToListAsync();
        var live = family.Where(t => t.RevokedAt == null).ToList();

        Assert.Single(live);
        Assert.Equal(wins[0].SuccessorId, live[0].Id);

        var revokedParent = family.Single(t => t.Id == parent.Id);
        Assert.NotNull(revokedParent.RevokedAt);
        Assert.Equal(wins[0].SuccessorId, revokedParent.ReplacedByTokenId);
    }

    [Fact]
    public async Task Http_TwoParallelRefresh_SameCookie_DoesNotLeaveTwoLiveSuccessors()
    {
        var email = $"cas-http-{Guid.NewGuid():N}@test.local";
        var user = await TestHelpers.SeedUserAsync(_factory, email);

        string refreshCookie;
        string familyId;
        using (var seedScope = _factory.Services.CreateScope())
        {
            var userManager = seedScope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var tracked = await userManager.FindByIdAsync(user.Id);
            Assert.NotNull(tracked);
            var stamp = await userManager.GetSecurityStampAsync(tracked);
            var svc = seedScope.ServiceProvider.GetRequiredService<IRefreshTokenService>();
            var issued = await svc.CreateAsync(user.Id, stamp);
            Assert.False(string.IsNullOrEmpty(issued.Token));
            refreshCookie = issued.Token!;
            familyId = issued.FamilyId;
        }

        using var clientA = CreateClientWithForcedRefreshCookie(refreshCookie);
        using var clientB = CreateClientWithForcedRefreshCookie(refreshCookie);

        var csrfA = await TestHelpers.GetCsrfTokenAsync(clientA, "/auth/csrfToken");
        var csrfB = await TestHelpers.GetCsrfTokenAsync(clientB, "/auth/csrfToken");

        var barrier = new Barrier(2);
        async Task<HttpResponseMessage> Refresh(HttpClient client, string csrf)
        {
            barrier.SignalAndWait(TimeSpan.FromSeconds(10));
            using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/refresh");
            request.Headers.Add("RequestVerificationToken", csrf);
            return await client.SendAsync(request);
        }

        var responses = await Task.WhenAll(Refresh(clientA, csrfA), Refresh(clientB, csrfB));
        var statuses = responses.Select(r => r.StatusCode).ToArray();
        var okCount = statuses.Count(s => s == HttpStatusCode.OK);
        var badCount = statuses.Count(s => s == HttpStatusCode.BadRequest);

        using var checkScope = _factory.Services.CreateScope();
        var db = checkScope.ServiceProvider.GetRequiredService<TestDbContext>();
        var family = await db.Set<RefreshToken>().Where(t => t.FamilyId == familyId).ToListAsync();
        var liveCount = family.Count(t => t.RevokedAt == null);

        Assert.True(
            liveCount == 1,
            $"Expected exactly one live successor. statuses=[{string.Join(",", statuses)}], " +
            $"ok={okCount}, bad={badCount}, family={family.Count}, live={liveCount}, " +
            $"liveIds=[{string.Join(",", family.Where(t => t.RevokedAt == null).Select(t => t.Id))}]");

        // At most one refresh may succeed; the other must fail (or both fail only if unexpected).
        Assert.True(okCount <= 1, $"Expected at most one OK refresh, got {okCount}.");
        Assert.True(
            okCount + badCount == 2,
            $"Expected OK/BadRequest only, got statuses=[{string.Join(",", statuses)}].");
    }

    private HttpClient CreateClientWithForcedRefreshCookie(string refreshTokenValue)
    {
        var client = _factory.CreateDefaultClient(new ForceRefreshCookieHandler(refreshTokenValue));
        TestHelpers.AttachWebAuthnOrigin(client);
        return client;
    }

    private sealed class ForceRefreshCookieHandler : DelegatingHandler
    {
        private readonly string _refreshTokenValue;

        public ForceRefreshCookieHandler(string refreshTokenValue)
        {
            _refreshTokenValue = refreshTokenValue;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var forced = $"{RefreshTokenCookieWriter.CookieName}={_refreshTokenValue}";
            if (request.Headers.TryGetValues("Cookie", out var existing))
            {
                var merged = new List<string>();
                foreach (var header in existing)
                {
                    var parts = header.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Where(p => !p.StartsWith(RefreshTokenCookieWriter.CookieName + "=", StringComparison.Ordinal))
                        .ToList();
                    if (parts.Count > 0)
                    {
                        merged.Add(string.Join("; ", parts));
                    }
                }

                request.Headers.Remove("Cookie");
                foreach (var m in merged)
                {
                    request.Headers.TryAddWithoutValidation("Cookie", m);
                }
            }

            request.Headers.TryAddWithoutValidation("Cookie", forced);
            return base.SendAsync(request, cancellationToken);
        }
    }
}
