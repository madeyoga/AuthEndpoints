using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

public static class AuthEndpointsServiceCollectionExtensions
{
    /// <summary>
    /// Registers the cookie Identity facade: Identity API endpoints, EF stores, antiforgery,
    /// ReAuth, rate limiting, and (by default) passkey support.
    /// Hosts must still register <see cref="DbContext"/>, call <see cref="AuthEndpointsApplicationBuilderExtensions.UseAuthEndpoints"/>,
    /// <see cref="AuthEndpointsEndpointRouteBuilderExtensions.MapAuthEndpoints{TUser}"/>, and in Production
    /// provide a real <c>IEmailSender&lt;TUser&gt;</c> plus <c>Passkeys.ServerDomain</c>.
    /// </summary>
    /// <remarks>
    /// For roles, prefer <see cref="AddAuthEndpoints{TUser, TRole, TContext}"/> so
    /// <c>IRoleStore</c> is registered. Do not chain bare <c>AddRoles</c> after this overload
    /// without calling <c>AddEntityFrameworkStores</c> again.
    /// For Identity bearer tokens, pass <see cref="AuthEndpointsSignIn.IdentityBearer"/> or set
    /// <see cref="AuthEndpointsOptions.SignIn"/>.
    /// </remarks>
    /// <returns>The <see cref="IdentityBuilder"/> for optional chaining.</returns>
    public static IdentityBuilder AddAuthEndpoints<TUser, TContext>(
        this IServiceCollection services,
        Action<AuthEndpointsOptions>? configure = null)
        where TUser : class, new()
        where TContext : DbContext
    {
        return AddAuthEndpointsCore<TUser, TContext>(services, configure, addRoles: null);
    }

    /// <summary>
    /// Same as <see cref="AddAuthEndpoints{TUser, TContext}(IServiceCollection, Action{AuthEndpointsOptions}?)"/>,
    /// with <see cref="AuthEndpointsOptions.SignIn"/> forced to <paramref name="signIn"/>.
    /// </summary>
    /// <returns>The <see cref="IdentityBuilder"/> for optional chaining.</returns>
    public static IdentityBuilder AddAuthEndpoints<TUser, TContext>(
        this IServiceCollection services,
        AuthEndpointsSignIn signIn,
        Action<AuthEndpointsOptions>? configure = null)
        where TUser : class, new()
        where TContext : DbContext
    {
        return AddAuthEndpointsCore<TUser, TContext>(
            services,
            WrapSignIn(signIn, configure),
            addRoles: null);
    }

    /// <summary>
    /// Same as <see cref="AddAuthEndpoints{TUser, TContext}(IServiceCollection, Action{AuthEndpointsOptions}?)"/>,
    /// and registers Identity roles (<typeparamref name="TRole"/>) before EF stores so <c>IRoleStore</c> is available.
    /// </summary>
    /// <returns>The <see cref="IdentityBuilder"/> for optional chaining.</returns>
    public static IdentityBuilder AddAuthEndpoints<TUser, TRole, TContext>(
        this IServiceCollection services,
        Action<AuthEndpointsOptions>? configure = null)
        where TUser : class, new()
        where TRole : class
        where TContext : DbContext
    {
        return AddAuthEndpointsCore<TUser, TContext>(
            services,
            configure,
            builder => builder.AddRoles<TRole>());
    }

    /// <summary>
    /// Same as <see cref="AddAuthEndpoints{TUser, TRole, TContext}(IServiceCollection, Action{AuthEndpointsOptions}?)"/>,
    /// with <see cref="AuthEndpointsOptions.SignIn"/> forced to <paramref name="signIn"/>.
    /// </summary>
    /// <returns>The <see cref="IdentityBuilder"/> for optional chaining.</returns>
    public static IdentityBuilder AddAuthEndpoints<TUser, TRole, TContext>(
        this IServiceCollection services,
        AuthEndpointsSignIn signIn,
        Action<AuthEndpointsOptions>? configure = null)
        where TUser : class, new()
        where TRole : class
        where TContext : DbContext
    {
        return AddAuthEndpointsCore<TUser, TContext>(
            services,
            WrapSignIn(signIn, configure),
            builder => builder.AddRoles<TRole>());
    }

    private static Action<AuthEndpointsOptions> WrapSignIn(
        AuthEndpointsSignIn signIn,
        Action<AuthEndpointsOptions>? configure)
    {
        return o =>
        {
            configure?.Invoke(o);
            o.SignIn = signIn;
        };
    }

    private static IdentityBuilder AddAuthEndpointsCore<TUser, TContext>(
        IServiceCollection services,
        Action<AuthEndpointsOptions>? configure,
        Func<IdentityBuilder, IdentityBuilder>? addRoles)
        where TUser : class, new()
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        var bootstrap = new AuthEndpointsOptions();
        configure?.Invoke(bootstrap);

        services.AddOptions<AuthEndpointsOptions>()
            .Configure(o =>
            {
                configure?.Invoke(o);
            })
            .ValidateOnStart();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<AuthEndpointsOptions>, AuthEndpointsOptionsValidator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<AuthEndpointsOptions>, AuthEndpointsEmailSenderValidator<TUser>>());

        var identityBuilder = services
            .AddIdentityApiEndpoints<TUser>(identity =>
            {
                identity.SignIn.RequireConfirmedAccount = bootstrap.RequireConfirmedAccount;
                // Version3 is required for passkey credential storage.
                identity.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                bootstrap.ConfigureIdentity?.Invoke(identity);
            });

        // Roles must be configured before AddEntityFrameworkStores so IRoleStore is registered.
        if (addRoles is not null)
        {
            identityBuilder = addRoles(identityBuilder);
        }

        identityBuilder = identityBuilder
            .AddEntityFrameworkStores<TContext>()
            .AddDefaultTokenProviders();

        services.AddAuthorization();
        services.AddAntiforgery();
        services.AddCookieAuthEndpoints();
        if (bootstrap.SignIn == AuthEndpointsSignIn.IdentityBearer)
        {
            services.AddBearerAuthEndpoints();
        }

        if (bootstrap.Passkeys.Enabled)
        {
            services.AddPasskeyEndpoints<TUser>();
            services.Configure<IdentityPasskeyOptions>(passkeys =>
            {
                if (!string.IsNullOrWhiteSpace(bootstrap.Passkeys.ServerDomain))
                {
                    passkeys.ServerDomain = bootstrap.Passkeys.ServerDomain;
                }

                bootstrap.ConfigurePasskeys?.Invoke(passkeys);
            });
        }

        if (bootstrap.Jwt.Enabled)
        {
            services.AddJwtEndpoints<TUser, TContext>(jwt =>
            {
                bootstrap.Jwt.Configure?.Invoke(jwt);
            });
        }

        return identityBuilder;
    }
}
