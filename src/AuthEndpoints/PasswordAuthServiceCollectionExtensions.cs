using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

/// <summary>
/// Decisions <c>AddPasswordAuth</c> already registered. <c>MapPasswordAuth</c> maps this snapshot.
/// A later <c>Configure&lt;PasswordAuthOptions&gt;</c> that changes session, path, or passkey domain fails validation.
/// </summary>
internal sealed class PasswordAuthRegistration
{
    public PasswordAuthRegistration(AuthEndpointsSession session, string path, string? serverDomain)
    {
        Session = session;
        Path = path;
        ServerDomain = serverDomain;
    }

    public AuthEndpointsSession Session { get; }

    public string Path { get; }

    public string? ServerDomain { get; }

    public bool PasskeysMapped => !string.IsNullOrWhiteSpace(ServerDomain);
}

public static class PasswordAuthServiceCollectionExtensions
{
    /// <summary>
    /// Registers the password facade: Identity, password sign-up, sign-in, and recovery,
    /// account management, one session (cookie or JWT), and passkeys when
    /// <see cref="PasskeyScenarioOptions.ServerDomain"/> is set.
    /// Hosts must call <c>UseAuthEndpoints</c> and <c>MapPasswordAuth&lt;TUser&gt;</c>,
    /// and in Production provide a real <c>IEmailSender&lt;TUser&gt;</c>.
    /// Do not also call <c>AddAuthEndpoints</c>.
    /// </summary>
    /// <remarks>
    /// This overload registers Identity without roles.
    /// For roles, call <see cref="AddPasswordAuth{TUser, TRole, TContext}(IServiceCollection, Action{PasswordAuthOptions}?)"/>
    /// so <c>AddRoles</c> runs before <c>AddEntityFrameworkStores</c>.
    /// Do not chain bare <c>AddRoles</c> after this overload.
    /// </remarks>
    public static IdentityBuilder AddPasswordAuth<TUser, TContext>(
        this IServiceCollection services,
        Action<PasswordAuthOptions>? configure = null)
        where TUser : class, new()
        where TContext : DbContext
    {
        return AddPasswordAuthCore<TUser, TContext>(services, configure, addRoles: null, roleType: null);
    }

    /// <summary>
    /// Same as <see cref="AddPasswordAuth{TUser, TContext}(IServiceCollection, Action{PasswordAuthOptions}?)"/>,
    /// and registers Identity roles (<typeparamref name="TRole"/>) before EF stores so
    /// <c>IRoleStore</c> is available and sign-in includes role claims.
    /// </summary>
    /// <remarks>
    /// <typeparamref name="TContext"/> must be an <c>IdentityDbContext&lt;TUser, TRole, TKey&gt;</c> or equivalent.
    /// </remarks>
    public static IdentityBuilder AddPasswordAuth<TUser, TRole, TContext>(
        this IServiceCollection services,
        Action<PasswordAuthOptions>? configure = null)
        where TUser : class, new()
        where TRole : class
        where TContext : DbContext
    {
        return AddPasswordAuthCore<TUser, TContext>(
            services,
            configure,
            builder => builder.AddRoles<TRole>(),
            typeof(TRole));
    }

    private static IdentityBuilder AddPasswordAuthCore<TUser, TContext>(
        IServiceCollection services,
        Action<PasswordAuthOptions>? configure,
        Func<IdentityBuilder, IdentityBuilder>? addRoles,
        Type? roleType)
        where TUser : class, new()
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.Any(descriptor => descriptor.ServiceType == typeof(PasswordAuthRegistration)))
        {
            throw new InvalidOperationException(
                "AddPasswordAuth was already called. A host registers the password facade once.");
        }

        var bootstrap = new PasswordAuthOptions();
        configure?.Invoke(bootstrap);
        services.AddSingleton(new PasswordAuthRegistration(
            bootstrap.Session,
            bootstrap.Path,
            bootstrap.Passkeys.ServerDomain));

        services.AddOptions<PasswordAuthOptions>()
            .Configure(o => configure?.Invoke(o))
            .ValidateOnStart();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<PasswordAuthOptions>, PasswordAuthOptionsValidator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<PasswordAuthOptions>, PasswordAuthEmailSenderValidator<TUser>>());

        // Roles must be configured before AddEntityFrameworkStores so IRoleStore is registered.
        var identityBuilder = services.AddAuthEndpointsIdentity<TUser, TContext>(
            identity =>
            {
                identity.SignIn.RequireConfirmedAccount = bootstrap.RequireConfirmedAccount;
                bootstrap.ConfigureIdentity?.Invoke(identity);
            },
            addRoles,
            roleType);

        services.AddPasswordSignUpEndpoints();
        services.AddPasswordSignInEndpoints();
        services.AddPasswordRecoveryEndpoints();
        services.AddAccountManagementEndpoints();

        if (bootstrap.Session == AuthEndpointsSession.Jwt && bootstrap.Jwt is not null)
        {
            services.AddJwtEndpoints<TUser, TContext>(bootstrap.Jwt);
        }
        else if (bootstrap.Session == AuthEndpointsSession.Cookie)
        {
            services.AddCookieSessionEndpoints();
        }

        if (!string.IsNullOrWhiteSpace(bootstrap.Passkeys.ServerDomain))
        {
            var serverDomain = bootstrap.Passkeys.ServerDomain;
            services.AddModule<PasskeyEndpointsModule>();
            services.AddPasskeySignInEndpoints<TUser>();
            services.AddPasskeySignUpEndpoints<TUser>();
            services.AddPasskeyRegisterOptionsEndpoints();
            services.AddPasskeyManagementEndpoints();
            services.Configure<IdentityPasskeyOptions>(passkeys => passkeys.ServerDomain = serverDomain);
        }

        services.AddOptions<AuthEndpointsOptions>()
            .Configure<IOptions<PasswordAuthOptions>>((auth, password) =>
            {
                auth.EmailConfirmation.ConfirmEmailRedirectUri = password.Value.EmailConfirmation.ConfirmEmailRedirectUri;
                auth.EmailConfirmation.AllowedRedirectOrigins = password.Value.EmailConfirmation.AllowedRedirectOrigins;
            });

        return identityBuilder;
    }
}
