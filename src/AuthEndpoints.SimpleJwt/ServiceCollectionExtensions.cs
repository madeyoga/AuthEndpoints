using System.IdentityModel.Tokens.Jwt;
using AuthEndpoints.Core;
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
    private static SimpleJwtBuilder AddSimpleJwtCore<TUser, TContext>(this IServiceCollection services, SimpleJwtOptions options)
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

        services.TryAddScoped<IAuthenticator<TUser>, DefaultAuthenticator<TUser>>();
        services.TryAddScoped<IAccessTokenGenerator, AccessTokenGenerator>();
        services.TryAddScoped<IRefreshTokenService, RefreshTokenGenerator<TContext>>();
        services.TryAddScoped<IRefreshTokenValidator, RefreshTokenValidator>();
        services.TryAddScoped<IdentityErrorDescriber>();
        services.TryAddScoped<JwtSecurityTokenHandler>();
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
            new SimpleJwtOptionsConfigurator().PostConfigure("default", sjOptions);
            new SimpleJwtOptionsValidator(loggerFactory.CreateLogger<SimpleJwtOptionsValidator>()).Validate("default", sjOptions);
        }
        var configureOptions = ConfigureJwtBearerOptions(sjOptions);

        services.AddAuthorization();
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(configureOptions)
                .AddJwtBearer("jwt", configureOptions);
        services.AddIdentityCore<TUser>()
                .AddEntityFrameworkStores<TContext>()
                .AddDefaultTokenProviders();

        var builder1 = AddSimpleJwtCore<TUser, TContext>(services, sjOptions);

        var endpointsType = typeof(JwtEndpointDefinition<>).MakeGenericType(builder1.UserType);
        services.AddSingleton(typeof(IEndpointDefinition), endpointsType);
        return builder1;
    }

    private static Action<JwtBearerOptions> ConfigureJwtBearerOptions(SimpleJwtOptions sjOptions)
    {
        return options =>
        {
            options.TokenValidationParameters = sjOptions.AccessValidationParameters!;
            options.Events = new JwtBearerEvents()
            {
                OnMessageReceived = context =>
                {
                    if (context.Request.Cookies.ContainsKey("X-Access-Token"))
                    {
                        context.Token = context.Request.Cookies["X-Access-Token"];
                    }
                    return Task.CompletedTask;
                },
            };
        };
    }
}
