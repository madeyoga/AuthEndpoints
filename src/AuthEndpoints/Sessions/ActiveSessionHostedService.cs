using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Sessions;

/// <summary>Marks endpoints that issue Identity bearer tokens.</summary>
internal sealed class IdentityBearerEndpointMarker
{
    public static readonly IdentityBearerEndpointMarker Instance = new();

    private IdentityBearerEndpointMarker()
    {
    }
}

/// <summary>
/// Deletes expired and ended session records on a timer.
/// </summary>
internal sealed class ActiveSessionHostedService : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly ActiveSessionOptions _options;
    private readonly ILogger _logger;

    public ActiveSessionHostedService(
        IServiceProvider services,
        IOptions<ActiveSessionOptions> options,
        ILoggerFactory loggerFactory)
    {
        _services = services;
        _options = options.Value;
        _logger = loggerFactory.CreateLogger(AuthEndpointsModules.LogCategory);
    }

    internal static void Validate(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var provider = scope.ServiceProvider;
        // Resolving the store also runs its own checks, such as an EF Core store's check that the session table is mapped.
        StoreChecks.EnsureResolvable<IActiveSessionStore>(provider, "AddActiveSessions");

        if (AuthEndpointsFeatures.For(provider).Jwt)
        {
            if (provider.GetService<IRefreshTokenService>() is not ActiveSessionRefreshTokenService
                || provider.GetService<IAccessTokenGenerator>() is not ActiveSessionAccessTokenGenerator)
            {
                throw new InvalidOperationException(
                    "Call AddActiveSessions after AddJwtEndpoints and after any AddRefreshTokenService or AddAccessTokenGenerator.");
            }
        }

        if (UsesIdentityBearer(provider))
        {
            throw new InvalidOperationException(
                "Active sessions support cookie and JWT sign-in only. Identity bearer tokens are mapped; use AuthEndpointsSession.Cookie or AuthEndpointsSession.Jwt, or remove AddActiveSessions.");
        }
    }

    private static bool UsesIdentityBearer(IServiceProvider provider)
    {
        var dataSource = provider.GetService<EndpointDataSource>();
        if (dataSource is null)
        {
            return false;
        }

        var configuredDefault = provider.GetService<IOptions<SignInCompletionOptions>>()?.Value.Default;
        var defaultIsBearer = string.Equals(configuredDefault, SignInCompleters.IdentityBearer, StringComparison.Ordinal);

        foreach (var endpoint in dataSource.Endpoints)
        {
            var metadata = endpoint.Metadata;
            if (metadata.GetMetadata<IdentityBearerEndpointMarker>() is not null)
            {
                return true;
            }

            var selection = metadata.GetMetadata<SignInCompleterSelection>();
            if (selection is not null
                && string.Equals(selection.Name, SignInCompleters.IdentityBearer, StringComparison.Ordinal))
            {
                return true;
            }

            if (selection is null
                && defaultIsBearer
                && metadata.GetMetadata<HonorSignInCompletionDefault>() is not null)
            {
                return true;
            }
        }

        return false;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CleanupOnceAsync(_services);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Active session cleanup failed.");
            }

            try
            {
                await Task.Delay(_options.CleanupInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    internal static async Task<int> CleanupOnceAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<ActiveSessionService>().CleanupAsync();
    }
}

/// <summary>
/// Checks the setup once the request pipeline (and so every mapped endpoint) is built; a bad setup fails startup.
/// </summary>
internal sealed class ActiveSessionStartupFilter(IServiceProvider services) : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            next(app);
            ActiveSessionHostedService.Validate(services);
        };
    }
}
