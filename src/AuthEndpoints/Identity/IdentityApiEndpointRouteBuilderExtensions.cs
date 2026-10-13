using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Identity;

public static class IdentityApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps account lifecycle endpoints (register, confirm/resend, forgot/reset, manage, ReAuth).
    /// This is <c>MapPasswordEndpoints&lt;TUser&gt;(PasswordLoginMode.None)</c>,
    /// <see cref="ConfirmEmailEndpointRouteBuilderExtensions.MapConfirmEmailEndpoints{TUser}"/>,
    /// and <see cref="AccountManagementEndpointRouteBuilderExtensions.MapAccountManagementEndpoints{TUser}"/>.
    /// Passkey reauthentication options stay mapped, including when passkey services are not registered.
    /// Compose with <see cref="MapCookieAuthEndpoints{TUser}"/>, <see cref="MapBearerAuthEndpoints{TUser}"/>,
    /// or <c>MapJwtAuthEndpoints</c> for sign-in. Call <c>UseRateLimiter()</c> and <c>UseAntiforgery()</c>.
    /// </summary>
    /// <param name="confirmEmailEndpointName">
    /// Optional unique endpoint name for confirm-email link generation.
    /// The confirm route is mapped once per name in an app.
    /// </param>
    public static IEndpointConventionBuilder MapIdentityManagementApi<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        return MapIdentityManagementCore<TUser>(endpoints, confirmEmailEndpointName, emailCodeReAuth: true);
    }

    /// <summary>
    /// Facade management map. Keeps the 3.4.1 step-up surface: no email-code send route, and
    /// <c>authMethods.emailCode</c> stays false.
    /// </summary>
    internal static IEndpointConventionBuilder MapIdentityManagementApiPreserving3x<TUser>(
        this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        return MapIdentityManagementCore<TUser>(endpoints, confirmEmailEndpointName: null, emailCodeReAuth: false);
    }

    private static IEndpointConventionBuilder MapIdentityManagementCore<TUser>(
        IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName,
        bool emailCodeReAuth)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var password = endpoints.MapPasswordEndpoints<TUser>(PasswordLoginMode.None, confirmEmailEndpointName);
        var confirm = endpoints.MapConfirmEmailEndpoints<TUser>(confirmEmailEndpointName);
        var account = endpoints.MapAccountManagementEndpoints<TUser>(
            confirmEmailEndpointName,
            alwaysMapPasskeyOptions: true,
            emailCodeReAuth: emailCodeReAuth);
        return new CompositeEndpointConventionBuilder(password, confirm, account);
    }

    internal static string DefaultConfirmEmailEndpointName<TUser>()
        where TUser : class
        => AuthEndpointsEndpointNames.ConfirmEmail<TUser>();

    /// <summary>
    /// Maps password register, login, forgot-password, and reset-password routes.
    /// Login uses <see cref="PasswordLoginMode.Cookie"/> unless
    /// <see cref="SignInCompletionOptions.Default"/> names a completer for this user.
    /// Also maps confirm-email when the default endpoint name is not mapped yet.
    /// </summary>
    public static IEndpointConventionBuilder MapPasswordEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        return MapPasswordCore<TUser>(
            endpoints,
            PasswordLoginMode.Cookie,
            completer: null,
            confirmEmailEndpointName: null,
            honorDefault: true);
    }

    /// <summary>
    /// Maps password routes with an explicit <paramref name="login"/> mode.
    /// Also maps confirm-email when <paramref name="confirmEmailEndpointName"/> is not mapped yet.
    /// <see cref="PasswordLoginMode.None"/> omits <c>POST /login</c> so a session map can own that route.
    /// An explicit mode keeps the 3.4.1 <c>PasswordSignInAsync</c> handler and does not apply
    /// <see cref="SignInCompletionOptions.Default"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapPasswordEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        PasswordLoginMode login,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        return MapPasswordCore<TUser>(endpoints, login, completer: null, confirmEmailEndpointName, honorDefault: false);
    }

    /// <summary>
    /// Maps password routes and finishes <c>POST /login</c> with the built-in completer for <paramref name="session"/>.
    /// A session always maps <c>POST /login</c>.
    /// </summary>
    public static IEndpointConventionBuilder MapPasswordEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        AuthEndpointsSession session,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return MapPasswordCore<TUser>(
            endpoints,
            PasswordLoginMode.Cookie,
            SignInCompleterMap.FromSession(session),
            confirmEmailEndpointName,
            honorDefault: false);
    }

    /// <summary>
    /// Maps password routes and finishes <c>POST /login</c> with the keyed completer <paramref name="completer"/>.
    /// A completer name always maps <c>POST /login</c>.
    /// </summary>
    public static IEndpointConventionBuilder MapPasswordEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string completer,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(completer);
        return MapPasswordCore<TUser>(
            endpoints,
            PasswordLoginMode.Cookie,
            completer,
            confirmEmailEndpointName,
            honorDefault: false);
    }

    private static IEndpointConventionBuilder MapPasswordCore<TUser>(
        IEndpointRouteBuilder endpoints,
        PasswordLoginMode login,
        string? completer,
        string? confirmEmailEndpointName,
        bool honorDefault)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        AuthEndpointsModules.WarnIfMissing<PasswordEndpointsModule>(
            endpoints,
            "AddPasswordEndpoints",
            "MapPasswordEndpoints");

        confirmEmailEndpointName ??= AuthEndpointsEndpointNames.ConfirmEmail<TUser>();
        var selected = completer;
        if (selected is null && honorDefault && login != PasswordLoginMode.None)
        {
            var configured = endpoints.ServiceProvider.GetService<IOptions<SignInCompletionOptions>>()?.Value.Default;
            if (!string.IsNullOrWhiteSpace(configured))
            {
                selected = configured;
            }
        }

        var routeGroup = endpoints.MapGroup("");
        IdentityEndpointRoutes.MapRegister<TUser>(routeGroup, confirmEmailEndpointName, nameof(MapPasswordEndpoints));
        routeGroup.MapConfirmEmailEndpoints<TUser>(confirmEmailEndpointName);
        IdentityEndpointRoutes.MapPasswordLogin<TUser>(routeGroup, login, nameof(MapPasswordEndpoints), selected);
        IdentityEndpointRoutes.MapForgotPassword<TUser>(routeGroup, nameof(MapPasswordEndpoints));
        IdentityEndpointRoutes.MapResetPassword<TUser>(routeGroup, nameof(MapPasswordEndpoints));
        return routeGroup;
    }

    /// <summary>
    /// Maps Identity bearer sign-in endpoints (login, refresh, logout).
    /// Pair with <see cref="MapIdentityManagementApi{TUser}"/> or <see cref="MapPasswordEndpoints{TUser}"/> for register.
    /// Call <see cref="ServiceCollectionExtensions.AddBearerAuthEndpoints"/> and <c>UseRateLimiter()</c>.
    /// </summary>
    public static IEndpointConventionBuilder MapBearerAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        AuthEndpointsModules.WarnIfMissing<PasswordEndpointsModule>(
            endpoints,
            "AddPasswordEndpoints",
            "MapBearerAuthEndpoints");

        var routeGroup = endpoints.MapGroup("");
        IdentityEndpointRoutes.MapPasswordLogin<TUser>(routeGroup, PasswordLoginMode.IdentityBearer, nameof(MapBearerAuthEndpoints));
        routeGroup.MapBearerSessionEndpoints<TUser>();
        return routeGroup;
    }

    /// <summary>
    /// Maps <c>POST /refresh</c> and signed-in <c>POST /logout</c> for Identity bearer sessions.
    /// </summary>
    public static IEndpointConventionBuilder MapBearerSessionEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        AuthEndpointsModules.WarnIfMissing<BearerSessionEndpointsModule>(
            endpoints,
            "AddBearerSessionEndpoints",
            "MapBearerSessionEndpoints");

        var routeGroup = endpoints.MapGroup("");
        IdentityEndpointRoutes.MapBearerSession<TUser>(routeGroup, nameof(MapBearerSessionEndpoints));
        return routeGroup;
    }

    /// <summary>
    /// Maps Identity cookie sign-in endpoints (login, logout, csrfToken).
    /// Pair with <see cref="MapIdentityManagementApi{TUser}"/> for register/manage.
    /// Call <see cref="ServiceCollectionExtensions.AddCookieAuthEndpoints"/> and <c>UseRateLimiter()</c>.
    /// </summary>
    public static IEndpointConventionBuilder MapCookieAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        AuthEndpointsModules.WarnIfMissing<PasswordEndpointsModule>(
            endpoints,
            "AddPasswordEndpoints",
            "MapCookieAuthEndpoints");

        var routeGroup = endpoints.MapGroup("");
        IdentityEndpointRoutes.MapPasswordLogin<TUser>(routeGroup, PasswordLoginMode.Cookie, nameof(MapCookieAuthEndpoints));
        routeGroup.MapCookieSessionEndpoints<TUser>();
        return routeGroup;
    }

    /// <summary>
    /// Maps signed-in <c>POST /logout</c> and <c>GET /csrfToken</c> for application-cookie sessions.
    /// </summary>
    public static IEndpointConventionBuilder MapCookieSessionEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        AuthEndpointsModules.WarnIfMissing<CookieSessionEndpointsModule>(
            endpoints,
            "AddCookieSessionEndpoints",
            "MapCookieSessionEndpoints");

        var routeGroup = endpoints.MapGroup("");
        IdentityEndpointRoutes.MapCookieSession<TUser>(routeGroup, nameof(MapCookieSessionEndpoints));
        return routeGroup;
    }
}
