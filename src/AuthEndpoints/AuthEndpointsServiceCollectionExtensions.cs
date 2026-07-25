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
    /// Registers a auth stack: Identity API endpoints, EF stores, antiforgery,
    /// ReAuth, rate limiting, and (by default) passkey support.
    /// Hosts must still register <see cref="DbContext"/>, call <see cref="AuthEndpointsApplicationBuilderExtensions.UseAuthEndpoints"/>,
    /// <see cref="AuthEndpointsEndpointRouteBuilderExtensions.MapAuthEndpoints{TUser}"/>, and in Production
    /// provide a real <c>IEmailSender&lt;TUser&gt;</c> plus <c>Passkeys.ServerDomain</c>.
    /// </summary>
    /// <returns>The <see cref="IdentityBuilder"/> for optional chaining (e.g. <c>AddRoles</c>).</returns>
    public static IdentityBuilder AddAuthEndpoints<TUser, TContext>(
        this IServiceCollection services,
        Action<AuthEndpointsOptions>? configure = null)
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
            })
            .AddEntityFrameworkStores<TContext>()
            .AddDefaultTokenProviders();

        services.AddAuthorization();
        services.AddAntiforgery();
        services.AddCookieAuthEndpoints();

        if (bootstrap.Passkeys.Enabled)
        {
            services.AddPasskeyEndpoints();
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
