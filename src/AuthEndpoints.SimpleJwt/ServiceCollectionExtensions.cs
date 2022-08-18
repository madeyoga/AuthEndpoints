using System.IdentityModel.Tokens.Jwt;
using AuthEndpoints.Core;
using AuthEndpoints.Core.Endpoints;
using AuthEndpoints.Infrastructure;
using AuthEndpoints.SimpleJwt.Core;
using AuthEndpoints.SimpleJwt.Core.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.SimpleJwt;

public static class ServiceCollectionExtensions
{
    public static SimpleJwtBuilder AddSimpleJwtCore<TUser, TContext>(this IServiceCollection services, SimpleJwtOptions options)
        where TUser : class
        where TContext : DbContext
    {
        services.AddSingleton(typeof(IOptions<SimpleJwtOptions>), Options.Create(options));

        var identityUserType = TypeHelper.FindGenericBaseType(typeof(TUser), typeof(IdentityUser<>));
        if (identityUserType == null)
        {
            throw new InvalidOperationException("Generic type TUser is not IdentityUser");
        }
        var keyType = identityUserType.GenericTypeArguments[0];

        var claimsProviderType = typeof(DefaultClaimsProvider<,>).MakeGenericType(keyType, typeof(TUser));
        services.TryAddScoped(typeof(IClaimsProvider<TUser>), claimsProviderType);
        services.TryAddScoped<IAccessTokenGenerator<TUser>, AccessTokenGenerator<TUser>>();
        services.TryAddScoped<IRefreshTokenGenerator<TUser>, RefreshTokenGenerator<TUser>>();
        services.TryAddScoped<ITokenGeneratorService<TUser>, TokenGeneratorService<TUser>>();
        services.TryAddScoped<IRefreshTokenValidator, RefreshTokenValidator>();
        services.TryAddScoped<JwtLoginService<TUser>>();
        services.TryAddScoped<IdentityErrorDescriber>();
        services.TryAddScoped<JwtSecurityTokenHandler>();

        // Stores
        services.TryAddScoped<IRefreshTokenRepository, RefreshTokenRepository<TContext>>();

        return new SimpleJwtBuilder(keyType, typeof(TUser), services, options);
    }

    /// <summary>
    /// Adds the SimpleJwt default system
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="services"></param>
    /// <returns>An <see cref="SimpleJwtBuilder"/> for creating and configuring the SimpleJwt system.</returns>
    public static SimpleJwtBuilder AddSimpleJwtEndpoints<TUser, TContext>(this IServiceCollection services)
        where TUser : class
        where TContext : DbContext
    {
        return services.AddSimpleJwtEndpoints<TUser, TContext>(o => { });
    }

    /// <summary>
    /// Adds and configures the Simple Jwt core system.
    /// </summary>
    /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
    /// <param name="services">The services available in the application.</param>
    /// <param name="setup">An action to configure the <see cref="SimpleJwtOptions"/>.</param>
    /// <returns>An <see cref="SimpleJwtBuilder"/> for creating and configuring the SimpleJwt system.</returns>
    public static SimpleJwtBuilder AddSimpleJwtEndpoints<TUser, TContext>(this IServiceCollection services, Action<SimpleJwtOptions> setup)
        where TUser : class
        where TContext : DbContext
    {
        var sjOptions = new SimpleJwtOptions();

        if (setup != null)
        {
            //services.AddOptions<SimpleJwtOptions>()
            //    .Configure(setup);
            setup.Invoke(sjOptions);
            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });
            new OptionsConfigurator().PostConfigure("default", sjOptions);
            new OptionsValidator(loggerFactory.CreateLogger<OptionsValidator>()).Validate("default", sjOptions);
        }

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = sjOptions.AccessValidationParameters!;
        })
        .AddJwtBearer("jwt", options =>
        {
            options.TokenValidationParameters = sjOptions.AccessValidationParameters!;
        });

        var builder = AddSimpleJwtCore<TUser, TContext>(services, sjOptions);

        var type = typeof(JwtEndpointDefinition<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
        services.AddSingleton(typeof(IEndpointDefinition), type);
        return builder;
    }
}
