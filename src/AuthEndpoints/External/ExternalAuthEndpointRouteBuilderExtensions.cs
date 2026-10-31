using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.ReAuth;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.External.OAuth;

public static class ExternalAuthEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps login and callback routes for every registered <see cref="IExternalAuthProvider"/>.
    /// The callback uses the cookie completer unless <see cref="SignInCompletionOptions.Default"/> names one,
    /// or the host registered <see cref="IExternalLoginCompleter{TUser}"/> with <see cref="ExternalAuthBuilder.AddCompleter{TCompleter}"/>.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        return MapExternalAuthCore<TUser>(endpoints, completer: null, scheme: null, provider: null);
    }

    /// <summary>
    /// Maps login and callback routes for every registered provider and finishes the callback
    /// with the built-in completer for <paramref name="session"/>. There is no two-factor step.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        AuthEndpointsSession session)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return MapExternalAuthCore<TUser>(endpoints, SignInCompleterMap.FromSession(session), scheme: null, provider: null);
    }

    /// <summary>
    /// Maps login and callback routes for every registered provider and finishes the callback
    /// with the keyed completer <paramref name="completer"/>. There is no two-factor step.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthEndpoints<TUser>(
        this IEndpointRouteBuilder endpoints,
        string completer)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(completer);
        return MapExternalAuthCore<TUser>(endpoints, completer, scheme: null, provider: null);
    }

    /// <summary>
    /// Maps login and callback routes for a single provider.
    /// The callback uses the cookie completer unless <see cref="SignInCompletionOptions.Default"/> names one,
    /// or the host registered a legacy completer.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthProvider<TUser>(
        this IEndpointRouteBuilder endpoints,
        IExternalAuthProvider provider)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(provider);
        return MapExternalAuthCore<TUser>(endpoints, completer: null, scheme: null, provider);
    }

    /// <summary>
    /// Maps login and callback routes for <paramref name="provider"/> and finishes the callback
    /// with the built-in completer for <paramref name="session"/>. There is no two-factor step.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthProvider<TUser>(
        this IEndpointRouteBuilder endpoints,
        IExternalAuthProvider provider,
        AuthEndpointsSession session)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(provider);
        return MapExternalAuthCore<TUser>(endpoints, SignInCompleterMap.FromSession(session), scheme: null, provider);
    }

    /// <summary>
    /// Maps login and callback routes for <paramref name="provider"/> and finishes the callback
    /// with the keyed completer <paramref name="completer"/>. There is no two-factor step.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthProvider<TUser>(
        this IEndpointRouteBuilder endpoints,
        IExternalAuthProvider provider,
        string completer)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentException.ThrowIfNullOrWhiteSpace(completer);
        return MapExternalAuthCore<TUser>(endpoints, completer, scheme: null, provider);
    }

    /// <summary>
    /// Maps login and callback routes for the registered provider with the given scheme.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthProvider<TUser>(
        this IEndpointRouteBuilder endpoints,
        string scheme)
        where TUser : class, new()
    {
        ArgumentException.ThrowIfNullOrEmpty(scheme);
        return MapExternalAuthCore<TUser>(endpoints, completer: null, scheme, provider: null);
    }

    /// <summary>
    /// Maps login and callback routes for <paramref name="scheme"/> and finishes the callback
    /// with the built-in completer for <paramref name="session"/>. There is no two-factor step.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthProvider<TUser>(
        this IEndpointRouteBuilder endpoints,
        string scheme,
        AuthEndpointsSession session)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrEmpty(scheme);
        return MapExternalAuthCore<TUser>(endpoints, SignInCompleterMap.FromSession(session), scheme, provider: null);
    }

    /// <summary>
    /// Maps login and callback routes for <paramref name="scheme"/> and finishes the callback
    /// with the keyed completer <paramref name="completer"/>. There is no two-factor step.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAuthProvider<TUser>(
        this IEndpointRouteBuilder endpoints,
        string scheme,
        string completer)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrEmpty(scheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(completer);
        return MapExternalAuthCore<TUser>(endpoints, completer, scheme, provider: null);
    }

    /// <summary>
    /// Maps account routes: list providers (anonymous), and list / link / unlink external logins.
    /// Works with zero registered providers: the provider and login lists return empty arrays.
    /// </summary>
    public static IEndpointConventionBuilder MapExternalAccountEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        EnsureExternalAuth(endpoints, nameof(MapExternalAccountEndpoints));

        var group = endpoints.MapGroup("");
        var providers = endpoints.ServiceProvider.GetServices<IExternalAuthProvider>().ToList();

        group.MapGet("/providers", ExternalAccountEndpoints<TUser>.ListProviders)
            .AllowAnonymous()
            .WithSummary("List the external sign-in providers this server offers.")
            .WithName("ExternalListProviders");

        group.MapGet("/logins", ExternalAccountEndpoints<TUser>.ListLogins)
            .RequireAuthEndpointsUser()
            .WithSummary("List linked external logins for the current user.")
            .WithName("ExternalListLogins");

        group.MapDelete("/logins/{loginProvider}/{providerKey}", ExternalAccountEndpoints<TUser>.RemoveLogin)
            .RequireAuthEndpointsUser()
            .RequireReauth()
            .RequireAntiforgery()
            .WithSummary("Unlink an external login from the current user.")
            .WithName("ExternalRemoveLogin");

        foreach (var provider in providers)
        {
            var scheme = provider.Scheme;
            group.MapGet($"/link/{scheme}", (
                string? returnUrl,
                HttpContext context,
                LinkGenerator linkGenerator,
                Microsoft.AspNetCore.Identity.SignInManager<TUser> signInManager,
                Microsoft.AspNetCore.Identity.UserManager<TUser> userManager,
                IEnumerable<IExternalAuthProvider> registered) =>
                    ExternalAccountEndpoints<TUser>.StartLink(
                        scheme, returnUrl, context, linkGenerator, signInManager, userManager, registered))
                .RequireAuthEndpointsUser()
                .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
                .WithSummary($"Start linking the {scheme} account.")
                .WithName($"ExternalStartLink-{scheme}");

            group.MapGet($"/link/{scheme}/callback", (
                string? returnUrl,
                string? error,
                string? error_description,
                Microsoft.AspNetCore.Identity.SignInManager<TUser> signInManager,
                Microsoft.AspNetCore.Identity.UserManager<TUser> userManager,
                IOptions<ExternalAuthOptions> options,
                HttpContext httpContext) =>
                    ExternalAccountEndpoints<TUser>.LinkCallback(
                        scheme, returnUrl, error, error_description, signInManager, userManager, options, httpContext))
                .RequireAuthEndpointsUser()
                .WithSummary($"Complete linking the {scheme} account.")
                .WithName(ExternalAccountEndpoints<TUser>.LinkCallbackEndpointName(scheme));
        }

        return group;
    }

    private static IEndpointConventionBuilder MapExternalAuthCore<TUser>(
        IEndpointRouteBuilder endpoints,
        string? completer,
        string? scheme,
        IExternalAuthProvider? provider)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var mapMethod = provider is not null || scheme is not null
            ? nameof(MapExternalAuthProvider)
            : nameof(MapExternalAuthEndpoints);
        EnsureExternalAuth(endpoints, mapMethod);
        PrepareCompleter<TUser>(endpoints, completer, mapMethod);

        if (provider is null && scheme is not null)
        {
            provider = endpoints.ServiceProvider
                .GetServices<IExternalAuthProvider>()
                .FirstOrDefault(p => string.Equals(p.Scheme, scheme, StringComparison.Ordinal));
            if (provider is null)
            {
                throw new InvalidOperationException(
                    $"No IExternalAuthProvider with scheme '{scheme}' is registered. Call Add{{Provider}} on ExternalAuthBuilder first.");
            }
        }

        var group = endpoints.MapGroup("");
        var providers = provider is null
            ? endpoints.ServiceProvider.GetServices<IExternalAuthProvider>().ToList()
            : [provider];
        foreach (var registered in providers)
        {
            MapProviderEndpoints<TUser>(group, registered, completer);
        }

        return group;
    }

    private static void PrepareCompleter<TUser>(IEndpointRouteBuilder endpoints, string? completer, string mapMethod)
        where TUser : class
    {
        if (completer is null)
        {
            var legacy = LegacySignInCompleters.ExternalWins<TUser>(endpoints.ServiceProvider);
            SignInCompleterMap.EnsureConfiguredDefault<TUser>(endpoints, mapMethod, legacy);
            if (legacy)
            {
                return;
            }

            var configured = endpoints.ServiceProvider.GetService<IOptions<SignInCompletionOptions>>()?.Value.Default;
            var name = string.IsNullOrWhiteSpace(configured) ? SignInCompleters.Cookie : configured;
            if (string.IsNullOrWhiteSpace(configured))
            {
                SignInCompleterMap.EnsureSelected<TUser>(endpoints, SignInCompleters.Cookie, mapMethod);
            }

            EnsureRefreshTransport(endpoints, name);
            return;
        }

        SignInCompleterMap.EnsureSelected<TUser>(endpoints, completer, mapMethod);
        EnsureRefreshTransport(endpoints, completer);
    }

    private static void EnsureRefreshTransport(IEndpointRouteBuilder endpoints, string completer)
    {
        if (!string.Equals(completer, SignInCompleters.Jwt, StringComparison.Ordinal))
        {
            return;
        }

        if (JwtRefreshDelivery.IsBody(JwtRefreshDelivery.Session(endpoints.ServiceProvider)))
        {
            throw new InvalidOperationException(JwtExternalBodyTransportValidator.Message);
        }
    }

    private static void EnsureExternalAuth(IEndpointRouteBuilder endpoints, string mapMethod)
    {
        if (AuthEndpointsModules.IsRegistered<ExternalAuthEndpointsModule>(endpoints.ServiceProvider))
        {
            return;
        }

        throw new InvalidOperationException(
            $"AddExternalAuthEndpoints was not called before {mapMethod}. Call AddExternalAuthEndpoints before {mapMethod}.");
    }

    private static void MapProviderEndpoints<TUser>(
        IEndpointRouteBuilder group,
        IExternalAuthProvider provider,
        string? completer)
        where TUser : class, new()
    {
        group.MapGet(provider.LoginPath, (
            string? returnUrl,
            HttpContext context,
            LinkGenerator linkGenerator,
            Microsoft.AspNetCore.Identity.SignInManager<TUser> signInManager) =>
                ExternalAuthEndpoints<TUser>.Login(returnUrl, context, linkGenerator, signInManager, provider))
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
            .WithSummary($"Start {provider.Scheme} OAuth sign-in.")
            .WithName($"ExternalLogin-{provider.Scheme}");

        var scheme = provider.Scheme;
        var callback = group.MapGet(provider.CallbackPath, (
            string? returnUrl,
            string? error,
            string? error_description,
            ExternalLoginService<TUser> loginService,
            IExternalLoginCompleter<TUser> legacy,
            IOptions<ExternalAuthOptions> options,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
                ExternalAuthEndpoints<TUser>.Callback(
                    scheme,
                    returnUrl,
                    error,
                    error_description,
                    loginService,
                    legacy,
                    options,
                    httpContext,
                    cancellationToken))
            .WithSummary($"Complete {provider.Scheme} OAuth sign-in.")
            .WithName(provider.CallbackEndpointName);

        if (completer is not null)
        {
            callback.WithMetadata(new SignInCompleterSelection(completer));
        }
        else
        {
            callback.WithMetadata(new HonorSignInCompletionDefault());
        }
    }
}
