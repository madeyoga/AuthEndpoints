using System.IdentityModel.Tokens.Jwt;
using AuthEndpoints.Core.Endpoints;
using AuthEndpoints.Core.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Core;

/// <summary>
/// Provides extensions to easily bootstrap authendpoints
/// </summary>
public static class ServiceCollectionExtensions
{
    internal static AuthEndpointsBuilder ConfigureServices<TUser>(IServiceCollection services, AuthEndpointsOptions endpointsOptions)
        where TUser : class
    {
        var identityUserType = FindGenericBaseType(typeof(TUser), typeof(IdentityUser<>));
        if (identityUserType == null)
        {
            throw new InvalidOperationException("Generic type TUser is not IdentityUser");
        }

        var keyType = identityUserType.GenericTypeArguments[0];

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = endpointsOptions.AccessValidationParameters!;
        })
        .AddJwtBearer("jwt", options =>
        {
            options.TokenValidationParameters = endpointsOptions.AccessValidationParameters!;
        });
        services.AddAuthorization();

        services.AddSingleton(typeof(IOptions<AuthEndpointsOptions>), Options.Create(endpointsOptions));

        // Add authendpoints core services
        var claimsProviderType = typeof(DefaultClaimsProvider<,>).MakeGenericType(keyType, typeof(TUser));
        services.TryAddScoped(typeof(IClaimsProvider<TUser>), claimsProviderType);

        services.TryAddScoped<IAccessTokenGenerator<TUser>, AccessTokenGenerator<TUser>>();
        services.TryAddScoped<IRefreshTokenGenerator<TUser>, RefreshTokenGenerator<TUser>>();
        services.TryAddScoped<ITokenGeneratorService<TUser>, TokenGeneratorService<TUser>>();

        services.TryAddScoped<IRefreshTokenValidator, RefreshTokenValidator>();
        services.TryAddScoped<IAuthenticator<TUser>, DefaultAuthenticator<TUser>>();

        services.TryAddSingleton<IEmailFactory, DefaultMessageFactory>();
        services.TryAddSingleton<IEmailSender, DefaultEmailSender>();

        var identityBuilder = services.AddIdentityCore<TUser>()
            .AddDefaultTokenProviders();

        services.TryAddScoped<IdentityErrorDescriber>();
        services.TryAddScoped<JwtSecurityTokenHandler>();

        return new AuthEndpointsBuilder(keyType, typeof(TUser), services, endpointsOptions);
    }

    /// <summary>
    /// Adds the AuthEndpoints core services
    /// </summary>
    /// <typeparam name="TUserKey"></typeparam>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="services"></param>
    /// <returns>An <see cref="AuthEndpointsBuilder"/> for creating and configuring the AuthEndpoints system.</returns>
    public static AuthEndpointsBuilder AddAuthEndpoints<TUser>(this IServiceCollection services)
        where TUser : class
    {
        return services.AddAuthEndpoints<TUser>(o => { });
    }

    /// <summary>
    /// Adds the AuthEndpoints core services
    /// </summary>
    /// <typeparam name="TUserKey"></typeparam>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="services"></param>
    /// <returns>An <see cref="AuthEndpointsBuilder"/> for creating and configuring the AuthEndpoints system.</returns>
    public static AuthEndpointsBuilder AddAuthEndpointsCore<TUser>(this IServiceCollection services)
        where TUser : class
    {
        return services.AddAuthEndpointsCore<TUser>(o => { });
    }

    /// <summary>
    /// Adds and configures the AuthEndpoints core system.
    /// </summary>
    /// <typeparam name="TUserKey">The type representing a User's primary key in the system.</typeparam>
    /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
    /// <param name="services">The services available in the application.</param>
    /// <param name="setup">An action to configure the <see cref="AuthEndpointsOptions"/>.</param>
    /// <returns>An <see cref="AuthEndpointsBuilder"/> for creating and configuring the AuthEndpoints system.</returns>
    public static AuthEndpointsBuilder AddAuthEndpoints<TUser>(this IServiceCollection services, Action<AuthEndpointsOptions> setup)
        where TUser : class
    {
        var options = new AuthEndpointsOptions();

        if (setup != null)
        {
            setup.Invoke(options);
            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });
            new OptionsConfigurator().PostConfigure("default", options);
            new OptionsValidator(loggerFactory.CreateLogger<OptionsValidator>()).Validate("default", options);
        }

        return ConfigureServices<TUser>(services, options);
    }

    /// <summary>
    /// Adds and configures the AuthEndpoints core system.
    /// </summary>
    /// <typeparam name="TUserKey">The type representing a User's primary key in the system.</typeparam>
    /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
    /// <param name="services">The services available in the application.</param>
    /// <param name="setup">An action to configure the <see cref="AuthEndpointsOptions"/>.</param>
    /// <returns>An <see cref="AuthEndpointsBuilder"/> for creating and configuring the AuthEndpoints system.</returns>
    public static AuthEndpointsBuilder AddAuthEndpointsCore<TUser>(this IServiceCollection services, Action<AuthEndpointsOptions> setup)
        where TUser : class
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

        return ConfigureServices<TUser>(services, options);
    }

    /// <summary>
    /// Add endpoint definition
    /// </summary>
    /// <typeparam name="TEndpointDefinition"></typeparam>
    /// <param name="builder"></param>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public static IServiceCollection AddEndpointDefinition<TEndpointDefinition>(this IServiceCollection services)
        where TEndpointDefinition : IEndpointDefinition
    {
        services.AddSingleton(typeof(IEndpointDefinition), typeof(TEndpointDefinition));
        return services;
    }

    /// <summary>
    /// Add endpoint definition
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="definitionType"></param>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public static IServiceCollection AddEndpointDefinition(this IServiceCollection services, Type definitionType)
    {
        services.AddSingleton(typeof(IEndpointDefinition), definitionType);
        return services;
    }

    private static Type? FindGenericBaseType(Type currentType, Type genericBaseType)
    {
        Type? type = currentType;
        while (type != null)
        {
            var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
            if (genericType != null && genericType == genericBaseType)
            {
                return type;
            }
            type = type.BaseType;
        }
        return null;
    }
}
