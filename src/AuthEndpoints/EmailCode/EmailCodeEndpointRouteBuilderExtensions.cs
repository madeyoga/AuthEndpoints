using AuthEndpoints.Identity;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.EmailCode;

public static class EmailCodeEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps <c>POST /emailCode/send</c> and <c>POST /emailCode/verify</c>.
    /// Send uses <see cref="AuthEndpointsConstants.EmailCodeSendPolicy"/>.
    /// Verify uses <see cref="AuthEndpointsConstants.LoginPolicy"/>.
    /// Neither route requires antiforgery.
    /// Verify uses <see cref="SignInCompletionOptions.Default"/> when it names a completer, otherwise Identity bearer
    /// (the application cookie with <c>useCookies</c> or <c>useSessionCookies</c>).
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
    /// Uses <see cref="SignInCompletionOptions.Default"/> when it names a completer, otherwise Identity bearer.
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
                SignInCompleterMap.EnsureConfiguredDefault<TUser>(endpoints, nameof(MapEmailCodeEndpoints));
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
                SignInCompleterMap.EnsureConfiguredDefault<TUser>(endpoints, nameof(MapEmailCodeSignInEndpoints));
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
        if (services.GetService<IServiceProviderIsService>() is { } isService && !isService.IsService(typeof(EmailCodeService)))
        {
            throw new InvalidOperationException($"Call {addMethod} before {mapMethod}.");
        }

        StoreChecks.EnsureResolvable<IEmailCodeStore>(services, "Email-code sign-in");
    }
}
