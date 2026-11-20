using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthEndpoints.OpenIddict;

/// <summary>Which OpenIddict endpoint a rate limited request is for.</summary>
public enum OAuthRateLimitedEndpoint
{
    /// <summary><c>POST /connect/token</c>.</summary>
    Token,

    /// <summary><c>POST /connect/revoke</c>.</summary>
    Revocation,
}

/// <summary>What a token or revocation endpoint limiter partitions on.</summary>
public sealed class OAuthRateLimitContext
{
    public OAuthRateLimitContext(HttpContext httpContext, OAuthRateLimitedEndpoint endpoint, string? clientId)
    {
        HttpContext = httpContext;
        Endpoint = endpoint;
        ClientId = clientId;
    }

    /// <summary>The request. <c>Connection.RemoteIpAddress</c> is the client's address once <c>UseForwardedHeaders</c> has run.</summary>
    public HttpContext HttpContext { get; }

    public OAuthRateLimitedEndpoint Endpoint { get; }

    /// <summary>The <c>client_id</c> as OpenIddict parsed it from the form or the <c>Authorization: Basic</c> header. Not yet authenticated.</summary>
    public string? ClientId { get; }
}

/// <summary>
/// Opt-in rate limit for <c>/connect/token</c> and <c>/connect/revoke</c>, which OpenIddict serves from its middleware, so
/// <c>RequireRateLimiting</c> cannot reach them. Off by default.
/// </summary>
public sealed class OAuthTokenRateLimitOptions
{
    /// <summary>
    /// Limit the token and revocation endpoints with the built-in fixed window, per endpoint, client id, and remote IP
    /// address. Default <see langword="false"/>. <c>AddTokenRateLimiter</c> turns the limit on with the host's own limiter.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>Requests allowed per endpoint, client id, and IP address in each <see cref="Window"/>. Default 60.</summary>
    public int PermitLimit { get; set; } = 60;

    /// <summary>The fixed window. Default 1 minute.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
}

/// <summary>Holds the limiter in use: the host's, or the built-in one when <see cref="OAuthTokenRateLimitOptions.Enabled"/> is set.</summary>
internal sealed class OAuthTokenRateLimiter : IDisposable
{
    private readonly PartitionedRateLimiter<OAuthRateLimitContext>? _limiter;
    private readonly bool _owned;

    public OAuthTokenRateLimiter(IOptions<OAuthServerOptions> options, IServiceProvider services, OAuthTokenRateLimiterFactory? factory = null)
    {
        if (factory is not null)
        {
            _limiter = factory.Create(services);
            return;
        }

        var settings = options.Value.TokenRateLimit;
        if (!settings.Enabled)
        {
            return;
        }

        var permits = settings.PermitLimit;
        var window = settings.Window;
        _owned = true;
        _limiter = PartitionedRateLimiter.Create<OAuthRateLimitContext, string>(context => RateLimitPartition.GetFixedWindowLimiter(
            DefaultPartition(context),
            _ => new FixedWindowRateLimiterOptions { PermitLimit = permits, Window = window, QueueLimit = 0 }));
    }

    public bool Active => _limiter is not null;

    public RateLimitLease Acquire(OAuthRateLimitContext context) => _limiter!.AttemptAcquire(context);

    /// <summary>Endpoint, client id (or none), and remote address. Separators cannot appear in the parts that matter.</summary>
    internal static string DefaultPartition(OAuthRateLimitContext context)
        => string.Join(
            '\n',
            context.Endpoint.ToString(),
            context.ClientId ?? string.Empty,
            context.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");

    public void Dispose()
    {
        if (_owned)
        {
            _limiter?.Dispose();
        }
    }
}

/// <summary>The host's limiter, from <c>AddTokenRateLimiter</c>. The host owns its lifetime.</summary>
internal sealed class OAuthTokenRateLimiterFactory(Func<IServiceProvider, PartitionedRateLimiter<OAuthRateLimitContext>> create)
{
    public PartitionedRateLimiter<OAuthRateLimitContext> Create(IServiceProvider services) => create(services);
}

/// <summary>
/// Runs first when OpenIddict validates a token or revocation request: after the request is parsed, before client
/// authentication or any database read. A rejected request gets <c>temporarily_unavailable</c>, sent as <c>429</c> with
/// <c>Retry-After</c> by <see cref="AttachRateLimitResponse{TContext}"/>.
/// </summary>
internal sealed class LimitTokenEndpointRequests(OAuthTokenRateLimiter limiter)
    : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenRequestContext>,
      IOpenIddictServerHandler<OpenIddictServerEvents.ValidateRevocationRequestContext>
{
    /// <summary>Transaction property that marks a rate limited request, with the retry delay in seconds (or empty).</summary>
    internal const string RejectedProperty = ".ae_rate_limited";

    public ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenRequestContext context)
    {
        Limit(context, OAuthRateLimitedEndpoint.Token, context.Request?.ClientId);
        return ValueTask.CompletedTask;
    }

    public ValueTask HandleAsync(OpenIddictServerEvents.ValidateRevocationRequestContext context)
    {
        Limit(context, OAuthRateLimitedEndpoint.Revocation, context.Request?.ClientId);
        return ValueTask.CompletedTask;
    }

    private void Limit(OpenIddictServerEvents.BaseValidatingContext context, OAuthRateLimitedEndpoint endpoint, string? clientId)
    {
        if (!limiter.Active || context.Transaction.GetHttpRequest()?.HttpContext is not { } http)
        {
            return;
        }

        using var lease = limiter.Acquire(new OAuthRateLimitContext(http, endpoint, string.IsNullOrEmpty(clientId) ? null : clientId));
        if (lease.IsAcquired)
        {
            return;
        }

        var retryAfter = lease.TryGetMetadata(MetadataName.RetryAfter, out var delay)
            ? Math.Max(1, (int)Math.Ceiling(delay.TotalSeconds)).ToString(CultureInfo.InvariantCulture)
            : string.Empty;
        context.Transaction.SetProperty(RejectedProperty, retryAfter);
        context.Reject(OpenIddictConstants.Errors.TemporarilyUnavailable, "Too many requests. Try again later.");
    }
}

/// <summary>
/// Turns OpenIddict's status code for a rate limited request into <c>429 Too Many Requests</c> and adds <c>Retry-After</c>,
/// before the JSON error body is written.
/// </summary>
internal sealed class AttachRateLimitResponse<TContext> : IOpenIddictServerHandler<TContext>
    where TContext : OpenIddictServerEvents.BaseRequestContext
{
    public ValueTask HandleAsync(TContext context)
    {
        if (context.Transaction.GetProperty<string>(LimitTokenEndpointRequests.RejectedProperty) is { } retryAfter
            && context.Transaction.GetHttpRequest()?.HttpContext.Response is { } response)
        {
            response.StatusCode = StatusCodes.Status429TooManyRequests;
            if (retryAfter.Length > 0)
            {
                response.Headers.RetryAfter = retryAfter;
            }
        }

        return ValueTask.CompletedTask;
    }
}
