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
    /// This is the building-block expansion below, with no facade-only routes.
    /// Hosts must call <c>UseAuthEndpoints</c> and <c>MapPasswordAuth&lt;TUser&gt;</c>,
    /// and in Production provide a real <c>IEmailSender&lt;TUser&gt;</c>.
    /// Do not also call <c>AddAuthEndpoints</c>.
    /// </summary>
    /// <remarks>
    /// <code>
    /// services.AddAuthEndpointsIdentity&lt;TUser, TContext&gt;(identity =&gt;
    /// {
    ///     identity.SignIn.RequireConfirmedAccount = options.RequireConfirmedAccount;
    ///     options.ConfigureIdentity?.Invoke(identity);
    /// });
    /// services.AddPasswordSignUpEndpoints();
    /// services.AddPasswordSignInEndpoints();
    /// services.AddPasswordRecoveryEndpoints();
    /// services.AddAccountManagementEndpoints();
    /// // Cookie:
    /// services.AddCookieSessionEndpoints();
    /// // Jwt (options.Jwt is required). AddJwtEndpoints applies SimpleJwtOptions.RefreshTokenTransport:
    /// services.AddJwtEndpoints&lt;TUser, TContext&gt;(options.Jwt);
    /// // When Passkeys.ServerDomain is set:
    /// services.AddPasskeyEndpoints&lt;TUser&gt;();
    /// services.Configure&lt;IdentityPasskeyOptions&gt;(passkeys =&gt; passkeys.ServerDomain = options.Passkeys.ServerDomain);
    /// // Confirm-email redirect, read by the shared handler:
    /// services.Configure&lt;AuthEndpointsOptions&gt;(auth =&gt;
    /// {
    ///     auth.EmailConfirmation.ConfirmEmailRedirectUri = options.EmailConfirmation.ConfirmEmailRedirectUri;
    ///     auth.EmailConfirmation.AllowedRedirectOrigins = options.EmailConfirmation.AllowedRedirectOrigins;
    /// });
    /// </code>
    /// </remarks>
    /// <returns>The <see cref="IdentityBuilder"/> for optional chaining.</returns>
    public static IdentityBuilder AddPasswordAuth<TUser, TContext>(
        this IServiceCollection services,
        Action<PasswordAuthOptions>? configure = null)
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

        var identityBuilder = services.AddAuthEndpointsIdentity<TUser, TContext>(identity =>
        {
            identity.SignIn.RequireConfirmedAccount = bootstrap.RequireConfirmedAccount;
            bootstrap.ConfigureIdentity?.Invoke(identity);
        });

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
            services.AddPasskeyEndpoints<TUser>();
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
