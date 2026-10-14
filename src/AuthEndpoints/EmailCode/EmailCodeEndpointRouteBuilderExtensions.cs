using AuthEndpoints.Identity;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.EmailCode;

public static class EmailCodeEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps <c>POST /emailCode/send</c> and <c>POST /emailCode/verify</c>.
    /// This is <see cref="MapEmailCodeSendEndpoints{TUser}"/> and
    /// <see cref="MapEmailCodeSignInEndpoints{TUser}()"/>.
    /// Send uses <see cref="AuthEndpointsConstants.EmailCodeSendPolicy"/>.
    /// Verify uses <see cref="AuthEndpointsConstants.LoginPolicy"/>.
    /// Neither route requires antiforgery.
    /// Verify keeps the 3.x completer: an explicitly registered
    /// <see cref="IEmailCodeSignInCompleter{TUser}"/>, otherwise Identity bearer.
    /// </summary>
    public static IEndpointConventionBuilder MapEmailCodeEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        return MapEmailCodeCore<TUser>(endpoints, completer: null, honorDefault: true);
    }

    /// <summary>
    /// Maps <c>POST /emailCode/send</c>. Shared: send does not start a session.
    /// </summary>
    public static IEndpointConventionBuilder MapEmailCodeSendEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        EnsureEmailCodeReady(endpoints, "AddEmailCodeSendEndpoints", nameof(MapEmailCodeSendEndpoints));
        return MapEmailCodeSendRoutes<TUser>(endpoints, nameof(MapEmailCodeSendEndpoints));
    }

    /// <summary>
    /// Maps <c>POST /emailCode/verify</c>.
    /// Verify keeps the 3.x completer unless <see cref="SignInCompletionOptions.Default"/> names one.
    /// Per session: call it on each session prefix. Also signs new users up when <c>AllowSignUp</c> is on.
    /// </summary>
    public static IEndpointConventionBuilder MapEmailCodeSignInEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        return MapEmailCodeSignInCore<TUser>(endpoints, completer: null, honorDefault: true);
    }

    /// <summary>
    /// Maps <c>POST /emailCode/verify</c> and finishes it with the built-in completer for <paramref name="session"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapEmailCodeSignInEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        AuthEndpointsSession session)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return MapEmailCodeSignInCore<TUser>(endpoints, SignInCompleterMap.FromSession(session), honorDefault: false);
    }

    /// <summary>
    /// Maps <c>POST /emailCode/verify</c> and finishes it with the keyed completer <paramref name="completer"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapEmailCodeSignInEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string completer)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(completer);
        return MapEmailCodeSignInCore<TUser>(endpoints, completer, honorDefault: false);
    }

    /// <summary>
    /// Facade email-code map. Keeps the 3.4.1 Identity bearer verify path and ignores
    /// <see cref="SignInCompletionOptions.Default"/>.
    /// </summary>
    internal static IEndpointConventionBuilder MapEmailCodeEndpointsPreserving3x<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        return MapEmailCodeCore<TUser>(endpoints, completer: null, honorDefault: false);
    }

    /// <summary>
    /// Maps email-code send and verify, and finishes verify with the built-in completer for <paramref name="session"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapEmailCodeEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        AuthEndpointsSession session)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return MapEmailCodeCore<TUser>(endpoints, SignInCompleterMap.FromSession(session), honorDefault: false);
    }

    /// <summary>
    /// Maps email-code send and verify, and finishes verify with the keyed completer <paramref name="completer"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapEmailCodeEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string completer)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(completer);
        return MapEmailCodeCore<TUser>(endpoints, completer, honorDefault: false);
    }

    private static IEndpointConventionBuilder MapEmailCodeCore<TUser>(
        IEndpointRouteBuilder endpoints,
        string? completer,
        bool honorDefault)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        EnsureEmailCodesMapped(endpoints.ServiceProvider);

        if (completer is null)
        {
            if (honorDefault)
            {
                SignInCompleterMap.EnsureConfiguredDefault<TUser>(
                    endpoints,
                    nameof(MapEmailCodeEndpoints),
                    LegacySignInCompleters.EmailCodeWins<TUser>(endpoints.ServiceProvider));
            }
        }
        else
        {
            SignInCompleterMap.EnsureSelected<TUser>(endpoints, completer, nameof(MapEmailCodeEndpoints));
        }

        var send = MapEmailCodeSendRoutes<TUser>(endpoints, nameof(MapEmailCodeEndpoints));
        var verify = MapEmailCodeSignInRoutes<TUser>(
            endpoints,
            completer,
            honorDefault,
            nameof(MapEmailCodeEndpoints));
        return new CompositeEndpointConventionBuilder(send, verify);
    }

    private static IEndpointConventionBuilder MapEmailCodeSignInCore<TUser>(
        IEndpointRouteBuilder endpoints,
        string? completer,
        bool honorDefault)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        EnsureEmailCodeReady(endpoints, "AddEmailCodeSignInEndpoints", nameof(MapEmailCodeSignInEndpoints));

        if (completer is null)
        {
            if (honorDefault)
            {
                SignInCompleterMap.EnsureConfiguredDefault<TUser>(
                    endpoints,
                    nameof(MapEmailCodeSignInEndpoints),
                    LegacySignInCompleters.EmailCodeWins<TUser>(endpoints.ServiceProvider));
            }
        }
        else
        {
            SignInCompleterMap.EnsureSelected<TUser>(endpoints, completer, nameof(MapEmailCodeSignInEndpoints));
        }

        return MapEmailCodeSignInRoutes<TUser>(
            endpoints,
            completer,
            honorDefault,
            nameof(MapEmailCodeSignInEndpoints));
    }

    private static IEndpointConventionBuilder MapEmailCodeSendRoutes<TUser>(
        IEndpointRouteBuilder endpoints,
        string mapMethod)
        where TUser : class, new()
    {
        var group = endpoints.MapGroup("");
        group.MapPost("/emailCode/send", EmailCodeEndpoints<TUser>.Send)
            .RequireRateLimiting(AuthEndpointsConstants.EmailCodeSendPolicy)
            .Track(endpoints, mapMethod);
        return group;
    }

    private static IEndpointConventionBuilder MapEmailCodeSignInRoutes<TUser>(
        IEndpointRouteBuilder endpoints,
        string? completer,
        bool honorDefault,
        string mapMethod)
        where TUser : class, new()
    {
        EmailCodeSignInMap.Mark(endpoints.ServiceProvider);
        var group = endpoints.MapGroup("");
        var verify = group.MapPost("/emailCode/verify", EmailCodeEndpoints<TUser>.Verify)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
            .Track(endpoints, mapMethod);
        if (completer is not null)
        {
            verify.WithMetadata(new SignInCompleterSelection(completer));
        }
        else if (honorDefault)
        {
            verify.WithMetadata(new HonorSignInCompletionDefault());
        }

        return group;
    }

    private static void EnsureEmailCodesMapped(IServiceProvider services)
    {
        EnsureEmailCodeReady(services, "AddEmailCodeEndpoints", "MapEmailCodeEndpoints");
    }

    private static void EnsureEmailCodeReady(IEndpointRouteBuilder endpoints, string addMethod, string mapMethod)
    {
        EnsureEmailCodeReady(endpoints.ServiceProvider, addMethod, mapMethod);
    }

    private static void EnsureEmailCodeReady(IServiceProvider services, string addMethod, string mapMethod)
    {
        var check = services.GetService<IEmailCodeModelCheck>();
        if (check is null)
        {
            throw new InvalidOperationException($"Call {addMethod} before {mapMethod}.");
        }

        check.EnsureMapped();
    }
}

internal interface IEmailCodeModelCheck
{
    void EnsureMapped();
}

internal sealed class EmailCodeModelCheck<TContext> : IEmailCodeModelCheck
    where TContext : DbContext
{
    private readonly IServiceScopeFactory _scopeFactory;

    public EmailCodeModelCheck(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public void EnsureMapped()
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TContext>();
        if (db.Model.FindEntityType(typeof(EmailCodeEntry)) is null)
        {
            throw new NotSupportedException(
                "MapEmailCodeEndpoints requires modelBuilder.UseEmailCodes() when email-code sign-in is enabled.");
        }
    }
}
