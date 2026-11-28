using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Sessions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints;

public static class EntityFrameworkCoreServiceCollectionExtensions
{
    /// <summary>
    /// Stores everything in <typeparamref name="TContext"/>: the ASP.NET Core Identity EF stores (users, and roles when
    /// <see cref="AuthEndpointsBuilder.AddRoles{TRole}"/> was called first), and the AuthEndpoints stores for email codes,
    /// refresh tokens and active sessions.
    /// </summary>
    /// <remarks>
    /// Map the tables you use in <typeparamref name="TContext"/>'s <c>OnModelCreating</c>: <c>UseEmailCodes()</c> with
    /// email code, <c>UseRefreshToken()</c> with JWT, and <c>UseActiveSessions()</c> with active sessions.
    /// A feature whose table is not mapped fails when its endpoints are mapped.
    /// </remarks>
    public static AuthEndpointsBuilder AddEntityFrameworkStores<TContext>(this AuthEndpointsBuilder builder)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddStores(new EntityFrameworkStores<TContext>());
    }

    /// <summary>
    /// Registers the AuthEndpoints EF stores for the <c>Add*Endpoints</c> building blocks: <see cref="IEmailCodeStore"/>,
    /// <see cref="IRefreshTokenStore"/>, <see cref="IActiveSessionStore"/> and
    /// <see cref="IUserCreateFailureHandler{TUser}"/>. Register the Identity stores separately, for example
    /// <c>services.AddAuthEndpointsIdentity&lt;TUser&gt;().AddEntityFrameworkStores&lt;TContext&gt;()</c>.
    /// With the <c>AddAuthEndpoints</c> builder, call <see cref="AddEntityFrameworkStores{TContext}"/> instead.
    /// </summary>
    public static IServiceCollection AddAuthEndpointsEntityFrameworkStores<TUser, TContext>(this IServiceCollection services)
        where TUser : class
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IEmailCodeStore>(sp => new EmailCodeStore<TContext>(sp.GetRequiredService<TContext>()));
        services.TryAddScoped<IRefreshTokenStore>(sp => new RefreshTokenStore<TContext>(sp.GetRequiredService<TContext>()));
        services.TryAddScoped<IActiveSessionStore>(sp => new ActiveSessionStore<TContext>(sp.GetRequiredService<TContext>()));
        services.TryAddScoped<IUserCreateFailureHandler<TUser>>(sp =>
            new EntityFrameworkUserCreateFailureHandler<TUser, TContext>(sp.GetRequiredService<TContext>()));
        return services;
    }

    private sealed class EntityFrameworkStores<TContext> : AuthEndpointsStores
        where TContext : DbContext
    {
        public override void Register<TUser>(IServiceCollection services, IdentityBuilder identity)
        {
            identity.AddEntityFrameworkStores<TContext>();
            services.AddAuthEndpointsEntityFrameworkStores<TUser, TContext>();
        }
    }
}
