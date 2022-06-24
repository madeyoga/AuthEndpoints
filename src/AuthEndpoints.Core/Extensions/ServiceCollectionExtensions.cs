using System.IdentityModel.Tokens.Jwt;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints;

/// <summary>
/// Provides extensions to easily bootstrap authendpoints
/// </summary>
public static class ServiceCollectionExtensions
{
    internal static AuthEndpointsBuilder ConfigureServices<TUserKey, TUser>(IServiceCollection services, AuthEndpointsOptions options)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        services.AddAuthorization();

        services.AddSingleton(typeof(IOptions<AuthEndpointsOptions>), Options.Create(options));
        //services.TryAddSingleton<IPostConfigureOptions<AuthEndpointsOptions>, OptionsConfigurator>();
        //services.TryAddSingleton<IValidateOptions<AuthEndpointsOptions>, OptionsValidator>();

        // Add authendpoints core services
        services.TryAddScoped<IClaimsProvider<TUser>, DefaultClaimsProvider<TUserKey, TUser>>();
        services.TryAddScoped<IJwtFactory, DefaultJwtFactory>();
        services.TryAddScoped<IJwtValidator, DefaultJwtValidator>();
        services.TryAddScoped<IAuthenticator<TUser>, DefaultAuthenticator<TUser>>();

        services.TryAddSingleton<IEmailFactory, DefaultMessageFactory>();
        services.TryAddSingleton<IEmailSender, DefaultEmailSender>();

        services.TryAddScoped<IdentityErrorDescriber>();
        services.TryAddScoped<JwtSecurityTokenHandler>();

        return new AuthEndpointsBuilder(typeof(TUserKey), typeof(TUser), services, options);
    }

    /// <summary>
    /// Adds the AuthEndpoints core services
    /// </summary>
    /// <typeparam name="TUserKey"></typeparam>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="services"></param>
    /// <returns>A <see cref="AuthEndpointsBuilder"/> for creating and configuring the AuthEndpoints system.</returns>
    public static AuthEndpointsBuilder AddAuthEndpoints<TUserKey, TUser>(this IServiceCollection services)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        return services.AddAuthEndpoints<TUserKey, TUser>(o => { });
    }

    /// <summary>
    /// Adds the AuthEndpoints core services
    /// </summary>
    /// <typeparam name="TUserKey"></typeparam>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="services"></param>
    /// <returns>A <see cref="AuthEndpointsBuilder"/> for creating and configuring the AuthEndpoints system.</returns>
    public static AuthEndpointsBuilder AddAuthEndpointsCore<TUserKey, TUser>(this IServiceCollection services)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        return services.AddAuthEndpoints<TUserKey, TUser>(o => { });
    }

    /// <summary>
    /// Adds and configures the AuthEndpoints core system.
    /// </summary>
    /// <typeparam name="TUserKey">The type representing a User's primary key in the system.</typeparam>
    /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
    /// <param name="services">The services available in the application.</param>
    /// <param name="setup">An action to configure the <see cref="AuthEndpointsOptions"/>.</param>
    /// <returns>A <see cref="AuthEndpointsBuilder"/> for creating and configuring the AuthEndpoints system.</returns>
    public static AuthEndpointsBuilder AddAuthEndpoints<TUserKey, TUser>(this IServiceCollection services, Action<AuthEndpointsOptions> setup)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        var options = new AuthEndpointsOptions();

        if (setup != null)
        {
            //services.AddOptions<AuthEndpointsOptions>()
            //    .Configure(setup);
            setup.Invoke(options);
            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });
            new OptionsConfigurator().PostConfigure("default", options);
            new OptionsValidator(loggerFactory.CreateLogger<OptionsValidator>()).Validate("default", options);
        }

        return ConfigureServices<TUserKey, TUser>(services, options);
    }

    /// <summary>
    /// Adds and configures the AuthEndpoints core system.
    /// </summary>
    /// <typeparam name="TUserKey">The type representing a User's primary key in the system.</typeparam>
    /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
    /// <param name="services">The services available in the application.</param>
    /// <param name="setup">An action to configure the <see cref="AuthEndpointsOptions"/>.</param>
    /// <returns>A <see cref="AuthEndpointsBuilder"/> for creating and configuring the AuthEndpoints system.</returns>
    public static AuthEndpointsBuilder AddAuthEndpointsCore<TUserKey, TUser>(this IServiceCollection services, Action<AuthEndpointsOptions> setup)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        var options = new AuthEndpointsOptions();

        if (setup != null)
        {
            //services.AddOptions<AuthEndpointsOptions>()
            //    .Configure(setup);
            setup.Invoke(options);
            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });
            new OptionsConfigurator().PostConfigure("default", options);
            new OptionsValidator(loggerFactory.CreateLogger<OptionsValidator>()).Validate("default", options);
        }

        return ConfigureServices<TUserKey, TUser>(services, options);
    }
}
