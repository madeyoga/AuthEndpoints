using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Identity;

public static class PasswordEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps <c>POST /register</c> and ensures confirm-email when that endpoint name is not mapped yet.
    /// Shared: register does not start a session. Mount it once, at the root or <c>sharedPath</c>.
    /// </summary>
    public static IEndpointConventionBuilder MapPasswordSignUpEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName = null)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return MapPasswordSignUpCore<TUser>(
            endpoints,
            confirmEmailEndpointName,
            nameof(MapPasswordSignUpEndpoints),
            warn: true);
    }

    /// <summary>
    /// Maps <c>POST /login</c> for the cookie session.
    /// Finishes through <see cref="SignInCompleters.Cookie"/> unless
    /// <see cref="SignInCompletionOptions.Default"/> names a completer.
    /// Per session: call it on each session prefix.
    /// </summary>
    public static IEndpointConventionBuilder MapPasswordSignInEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return MapPasswordSignInCore<TUser>(
            endpoints,
            PasswordLoginMode.Cookie,
            completer: null,
            nameof(MapPasswordSignInEndpoints),
            warn: true,
            honorDefault: true);
    }

    /// <summary>
    /// Maps <c>POST /login</c> for an explicit <paramref name="login"/> mode.
    /// <see cref="PasswordLoginMode.None"/> is rejected: this map exists to finish in a session.
    /// An explicit mode keeps the 3.4.1 <c>PasswordSignInAsync</c> handler.
    /// </summary>
    public static IEndpointConventionBuilder MapPasswordSignInEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        PasswordLoginMode login)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        if (login == PasswordLoginMode.None)
        {
            throw new ArgumentOutOfRangeException(
                nameof(login),
                login,
                "MapPasswordSignInEndpoints maps POST /login. Pass Cookie or IdentityBearer.");
        }

        return MapPasswordSignInCore<TUser>(
            endpoints,
            login,
            completer: null,
            nameof(MapPasswordSignInEndpoints),
            warn: true,
            honorDefault: false);
    }

    /// <summary>
    /// Maps <c>POST /login</c> and finishes it with the built-in completer for <paramref name="session"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapPasswordSignInEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        AuthEndpointsSession session)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return MapPasswordSignInCore<TUser>(
            endpoints,
            PasswordLoginMode.Cookie,
            SignInCompleterMap.FromSession(session),
            nameof(MapPasswordSignInEndpoints),
            warn: true,
            honorDefault: false);
    }

    /// <summary>
    /// Maps <c>POST /login</c> and finishes it with the keyed completer <paramref name="completer"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapPasswordSignInEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string completer)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(completer);
        return MapPasswordSignInCore<TUser>(
            endpoints,
            PasswordLoginMode.Cookie,
            completer,
            nameof(MapPasswordSignInEndpoints),
            warn: true,
            honorDefault: false);
    }

    /// <summary>
    /// Maps <c>POST /forgotPassword</c> and <c>POST /resetPassword</c>.
    /// Shared: recovery does not start a session.
    /// </summary>
    public static IEndpointConventionBuilder MapPasswordRecoveryEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return MapPasswordRecoveryCore<TUser>(endpoints, nameof(MapPasswordRecoveryEndpoints), warn: true);
    }

    internal static IEndpointConventionBuilder MapPasswordSignUpCore<TUser>(
        IEndpointRouteBuilder endpoints,
        string? confirmEmailEndpointName,
        string mapMethod,
        bool warn)
        where TUser : class, new()
    {
        if (warn)
        {
            AuthEndpointsModules.ThrowIfMissing<PasswordSignUpEndpointsModule>(
                endpoints,
                "AddPasswordSignUpEndpoints",
                mapMethod);
        }

        confirmEmailEndpointName ??= AuthEndpointsEndpointNames.ConfirmEmail<TUser>();
        var group = endpoints.MapGroup("");
        IdentityEndpointRoutes.MapRegister<TUser>(group, confirmEmailEndpointName, mapMethod);
        group.MapConfirmEmailEndpoints<TUser>(confirmEmailEndpointName);
        return group;
    }

    internal static IEndpointConventionBuilder MapPasswordSignInCore<TUser>(
        IEndpointRouteBuilder endpoints,
        PasswordLoginMode login,
        string? completer,
        string mapMethod,
        bool warn,
        bool honorDefault)
        where TUser : class, new()
    {
        if (warn)
        {
            AuthEndpointsModules.ThrowIfMissing<PasswordSignInEndpointsModule>(
                endpoints,
                "AddPasswordSignInEndpoints",
                mapMethod);
        }

        var choice = honorDefault
            ? ResolvePasswordCompleter(endpoints, login, completer, honorDefault: true)
            : new PasswordCompleterChoice(completer, AllowUnregisteredBuiltIn: false);

        if (choice.Name is null && login == PasswordLoginMode.None)
        {
            return EmptyEndpointConventionBuilder.Instance;
        }

        var group = endpoints.MapGroup("");
        IdentityEndpointRoutes.MapPasswordLogin<TUser>(
            group,
            login,
            mapMethod,
            choice.Name,
            choice.AllowUnregisteredBuiltIn);
        return group;
    }

    internal static PasswordCompleterChoice ResolvePasswordCompleter(
        IEndpointRouteBuilder endpoints,
        PasswordLoginMode login,
        string? completer,
        bool honorDefault)
    {
        if (completer is not null || !honorDefault || login == PasswordLoginMode.None)
        {
            return new PasswordCompleterChoice(completer, AllowUnregisteredBuiltIn: false);
        }

        var configured = endpoints.ServiceProvider.GetService<IOptions<SignInCompletionOptions>>()?.Value.Default;
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return new PasswordCompleterChoice(configured, AllowUnregisteredBuiltIn: false);
        }

        var builtIn = login == PasswordLoginMode.IdentityBearer
            ? SignInCompleters.IdentityBearer
            : SignInCompleters.Cookie;
        return new PasswordCompleterChoice(builtIn, AllowUnregisteredBuiltIn: true);
    }

    internal static IEndpointConventionBuilder MapPasswordRecoveryCore<TUser>(
        IEndpointRouteBuilder endpoints,
        string mapMethod,
        bool warn)
        where TUser : class, new()
    {
        if (warn)
        {
            AuthEndpointsModules.ThrowIfMissing<PasswordRecoveryEndpointsModule>(
                endpoints,
                "AddPasswordRecoveryEndpoints",
                mapMethod);
        }

        var group = endpoints.MapGroup("");
        IdentityEndpointRoutes.MapForgotPassword<TUser>(group, mapMethod);
        IdentityEndpointRoutes.MapResetPassword<TUser>(group, mapMethod);
        return group;
    }
}

internal readonly record struct PasswordCompleterChoice(string? Name, bool AllowUnregisteredBuiltIn);
