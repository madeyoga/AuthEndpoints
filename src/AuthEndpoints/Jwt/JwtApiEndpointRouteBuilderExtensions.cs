using AuthEndpoints.Identity;
using AuthEndpoints.SignIn;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Jwt;

public static class JwtApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps JWT auth endpoints (create, refresh, verify, logout, csrfToken).
    /// Call <see cref="ServiceCollectionExtensions.AddJwtEndpoints{TUser, TContext}"/>,
    /// <c>UseRateLimiter()</c>, and <c>UseAntiforgery()</c>.
    /// Pair with <c>MapIdentityManagementApi</c> for register/manage.
    /// </summary>
    public static IEndpointConventionBuilder MapJwtAuthEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var create = endpoints.MapJwtPasswordEndpoints<TUser>();
        var session = endpoints.MapJwtSessionEndpoints<TUser>();
        return new CompositeEndpointConventionBuilder(create, session);
    }

    /// <summary>
    /// Maps password JWT <c>POST /create</c> on the shared password pipeline and the Jwt completer.
    /// A wrong authenticator or recovery code counts toward lockout.
    /// <c>MapAuthEndpoints</c> keeps the 3.4.1 handler instead.
    /// </summary>
    public static IEndpointConventionBuilder MapJwtPasswordEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return MapJwtPasswordCore<TUser>(endpoints, preserve3x: false, nameof(MapJwtPasswordEndpoints), warn: true);
    }

    internal static IEndpointConventionBuilder MapJwtAuthEndpointsPreserving3x<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var create = MapJwtPasswordCore<TUser>(endpoints, preserve3x: true, nameof(MapJwtPasswordEndpoints), warn: true);
        var session = endpoints.MapJwtSessionEndpoints<TUser>();
        return new CompositeEndpointConventionBuilder(create, session);
    }

    internal static IEndpointConventionBuilder MapJwtPasswordCore<TUser>(
        IEndpointRouteBuilder endpoints,
        bool preserve3x,
        string mapMethod,
        bool warn)
        where TUser : class, new()
    {
        var routeGroup = endpoints.MapGroup("");
        if (preserve3x)
        {
            if (warn)
            {
                AuthEndpointsModules.ThrowIfMissing<JwtEndpointsModule>(
                    endpoints,
                    "AddJwtEndpoints",
                    mapMethod);
            }

            routeGroup.MapPost("/create", JwtEndpoints<TUser>.Create)
                .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
                .Track(endpoints, mapMethod);
        }
        else
        {
            SignInCompleterMap.EnsureSelected<TUser>(endpoints, SignInCompleters.Jwt, mapMethod);
            routeGroup.MapPost("/create", PasswordCompleterSignIn<TUser>.HandleCreate)
                .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
                .WithMetadata(new SignInCompleterSelection(SignInCompleters.Jwt))
                .Track(endpoints, mapMethod);
        }

        PasswordSignInMap.Mark(endpoints.ServiceProvider);
        return routeGroup;
    }

    /// <summary>
    /// Maps JWT <c>POST /refresh</c>, <c>GET /verify</c>, and <c>POST /logout</c>.
    /// Cookie transport also maps <c>GET /csrfToken</c> and requires antiforgery on refresh and logout.
    /// Body transport (<see cref="JwtSessionOptions.RefreshTokenTransport"/>) does not.
    /// </summary>
    public static IEndpointConventionBuilder MapJwtSessionEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        AuthEndpointsModules.ThrowIfMissing<JwtEndpointsModule>(
            endpoints,
            "AddJwtEndpoints",
            "MapJwtSessionEndpoints");

        var body = JwtRefreshDelivery.IsBody(JwtRefreshDelivery.Session(endpoints.ServiceProvider));
        var routeGroup = endpoints.MapGroup("");

        var refresh = routeGroup.MapPost("/refresh", JwtEndpoints<TUser>.Refresh)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy);
        if (!body)
        {
            refresh.RequireAntiforgery();
        }

        refresh.Track(endpoints, nameof(MapJwtSessionEndpoints));

        routeGroup.MapGet("/verify", JwtEndpoints<TUser>.Verify)
            .Track(endpoints, nameof(MapJwtSessionEndpoints));

        var logout = routeGroup.MapPost("/logout", JwtEndpoints<TUser>.Logout);
        if (!body)
        {
            logout.RequireAntiforgery();
        }

        logout.Track(endpoints, nameof(MapJwtSessionEndpoints));

        if (!body)
        {
            routeGroup.MapGet("/csrfToken", JwtEndpoints<TUser>.GetAntiforgeryToken)
                .Track(endpoints, nameof(MapJwtSessionEndpoints));
        }

        return routeGroup;
    }
}
