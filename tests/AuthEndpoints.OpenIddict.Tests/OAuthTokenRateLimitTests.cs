using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using static AuthEndpoints.OpenIddict.Tests.OAuthTestHost;

namespace AuthEndpoints.OpenIddict.Tests;

/// <summary>The opt-in rate limit on <c>/connect/token</c> and <c>/connect/revoke</c>.</summary>
public sealed class OAuthTokenRateLimitTests
{
    [Fact]
    public async Task Off_by_default()
    {
        await using var host = await StartAsync();
        using var anon = host.Client(cookies: false);
        for (var i = 0; i < 70; i++)
        {
            Assert.Equal(HttpStatusCode.BadRequest, (await TokenAsync(anon, RefreshGrant(SeededClientId, "nope"))).StatusCode);
        }
    }

    [Fact]
    public async Task The_request_over_the_limit_gets_429_with_an_oauth_error_and_retry_after()
    {
        await using var host = await StartAsync(options =>
        {
            options.TokenRateLimit.Enabled = true;
            options.TokenRateLimit.PermitLimit = 2;
            options.TokenRateLimit.Window = TimeSpan.FromMinutes(1);
        });
        var (user, _) = await host.UserAsync("limited");
        var (client, tokens) = await host.IssueAsync(user); // the code exchange, from its own address
        using var anon = host.Client(cookies: false);

        // Two requests from this address fit in the window.
        var first = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, tokens.RefreshToken)));
        var refreshed = await ReadTokenAsync(await TokenAsync(anon, RefreshGrant(client.ClientId, first.RefreshToken)));

        var rejected = await TokenAsync(anon, RefreshGrant(client.ClientId, refreshed.RefreshToken));
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        var body = JsonSerializer.Deserialize<JsonElement>(await rejected.Content.ReadAsStringAsync());
        Assert.Equal("temporarily_unavailable", body.GetProperty("error").GetString());
        Assert.False(string.IsNullOrEmpty(body.GetProperty("error_description").GetString()));
        var retryAfter = int.Parse(Assert.Single(rejected.Headers.GetValues("Retry-After")));
        Assert.InRange(retryAfter, 1, 60);

        // The refused request did not touch the grant: the refresh token still works for another client address.
        using var elsewhere = host.Client(cookies: false);
        await ReadTokenAsync(await TokenAsync(elsewhere, RefreshGrant(client.ClientId, refreshed.RefreshToken)));
    }

    [Fact]
    public async Task Partitions_are_per_client_and_per_address()
    {
        await using var host = await StartAsync(options =>
        {
            options.TokenRateLimit.Enabled = true;
            options.TokenRateLimit.PermitLimit = 1;
        });
        using var anon = host.Client(cookies: false);
        var first = await host.RegisterAsync("First");
        var second = await host.RegisterAsync("Second");

        Assert.Equal(HttpStatusCode.BadRequest, (await TokenAsync(anon, RefreshGrant(first.ClientId, "x"))).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await TokenAsync(anon, RefreshGrant(first.ClientId, "x"))).StatusCode);

        // Another client from the same address, and the same client from another address, have their own windows.
        Assert.Equal(HttpStatusCode.BadRequest, (await TokenAsync(anon, RefreshGrant(second.ClientId, "x"))).StatusCode);
        using var other = host.Client(cookies: false);
        Assert.Equal(HttpStatusCode.BadRequest, (await TokenAsync(other, RefreshGrant(first.ClientId, "x"))).StatusCode);
    }

    [Fact]
    public async Task A_new_client_id_on_each_request_still_hits_the_per_address_limit()
    {
        await using var host = await StartAsync(options =>
        {
            options.TokenRateLimit.Enabled = true;
            options.TokenRateLimit.PermitLimit = 2;
        });
        using var anon = host.Client(cookies: false);

        // The default per-address limit is 4 × PermitLimit. Made-up client ids get no fresh window.
        for (var i = 0; i < 8; i++)
        {
            // An unknown client is refused (invalid_client), but not rate limited yet.
            Assert.NotEqual(HttpStatusCode.TooManyRequests, (await TokenAsync(anon, RefreshGrant($"made-up-{Guid.NewGuid():N}", "x"))).StatusCode);
        }

        var rejected = await TokenAsync(anon, RefreshGrant($"made-up-{Guid.NewGuid():N}", "x"));
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.Equal("temporarily_unavailable", JsonSerializer.Deserialize<JsonElement>(await rejected.Content.ReadAsStringAsync()).GetProperty("error").GetString());
        Assert.True(rejected.Headers.Contains("Retry-After"));

        // Another address has its own budget.
        using var other = host.Client(cookies: false);
        Assert.Equal(HttpStatusCode.BadRequest, (await TokenAsync(other, RefreshGrant(SeededClientId, "x"))).StatusCode);
    }

    [Fact]
    public async Task The_per_address_limit_can_be_set()
    {
        await using var host = await StartAsync(options =>
        {
            options.TokenRateLimit.Enabled = true;
            options.TokenRateLimit.PermitLimit = 10;
            options.TokenRateLimit.PermitLimitPerAddress = 3;
        });
        using var anon = host.Client(cookies: false);

        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.BadRequest, (await TokenAsync(anon, RefreshGrant(SeededClientId, "x"))).StatusCode);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, (await TokenAsync(anon, RefreshGrant(SeededClientId, "x"))).StatusCode);
    }

    [Fact]
    public async Task The_revocation_endpoint_is_limited_on_its_own()
    {
        await using var host = await StartAsync(options =>
        {
            options.TokenRateLimit.Enabled = true;
            options.TokenRateLimit.PermitLimit = 1;
        });
        using var anon = host.Client(cookies: false);
        var form = new Dictionary<string, string> { ["token"] = "unknown", ["client_id"] = SeededClientId };

        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsync("/connect/revoke", new FormUrlEncodedContent(form))).StatusCode);
        var rejected = await anon.PostAsync("/connect/revoke", new FormUrlEncodedContent(form));
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.Equal("temporarily_unavailable", JsonSerializer.Deserialize<JsonElement>(await rejected.Content.ReadAsStringAsync()).GetProperty("error").GetString());
        Assert.True(rejected.Headers.Contains("Retry-After"));

        // The token endpoint has its own partition.
        Assert.Equal(HttpStatusCode.BadRequest, (await TokenAsync(anon, RefreshGrant(SeededClientId, "x"))).StatusCode);
    }

    [Fact]
    public async Task A_host_limiter_replaces_the_default_turns_the_limit_on_and_sees_the_client_id()
    {
        var seen = new ConcurrentQueue<(OAuthRateLimitedEndpoint Endpoint, string? ClientId)>();
        await using var host = await StartAsync(server: server => server.AddTokenRateLimiter(_ =>
            PartitionedRateLimiter.Create<OAuthRateLimitContext, string>(context =>
            {
                seen.Enqueue((context.Endpoint, context.ClientId));
                return RateLimitPartition.GetTokenBucketLimiter(context.ClientId ?? "", _ => new TokenBucketRateLimiterOptions
                {
                    TokenLimit = 1,
                    TokensPerPeriod = 1,
                    ReplenishmentPeriod = TimeSpan.FromHours(1),
                    QueueLimit = 0,
                });
            })));
        using var anon = host.Client(cookies: false);

        Assert.Equal(HttpStatusCode.BadRequest, (await TokenAsync(anon, RefreshGrant(SeededClientId, "x"))).StatusCode);
        var rejected = await TokenAsync(anon, RefreshGrant(SeededClientId, "x"));
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.Contains((OAuthRateLimitedEndpoint.Token, SeededClientId), seen);
    }

    [Fact]
    public async Task Bad_settings_fail_startup_when_enabled()
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(() => StartAsync(options =>
        {
            options.TokenRateLimit.Enabled = true;
            options.TokenRateLimit.PermitLimit = 0;
            options.TokenRateLimit.PermitLimitPerAddress = 0;
            options.TokenRateLimit.Window = TimeSpan.Zero;
        }));
        Assert.Contains("TokenRateLimit.PermitLimit", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("TokenRateLimit.PermitLimitPerAddress", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("TokenRateLimit.Window", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void The_default_partition_combines_endpoint_client_and_address()
    {
        var http = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        http.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.5");
        Assert.Equal(
            "Token\nclient-1\n203.0.113.5",
            OAuthTokenRateLimiter.DefaultPartition(new OAuthRateLimitContext(http, OAuthRateLimitedEndpoint.Token, "client-1")));
        Assert.Equal(
            "Revocation\n\n203.0.113.5",
            OAuthTokenRateLimiter.DefaultPartition(new OAuthRateLimitContext(http, OAuthRateLimitedEndpoint.Revocation, null)));
        Assert.Equal(
            "Token\n203.0.113.5",
            OAuthTokenRateLimiter.AddressPartition(new OAuthRateLimitContext(http, OAuthRateLimitedEndpoint.Token, "client-1")));
    }
}
