using System.IdentityModel.Tokens.Jwt;
using AuthEndpoints.Core;
using AuthEndpoints.Core.Endpoints;
using AuthEndpoints.Core.Services;
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

        services.TryAddScoped<IClaimsProvider, DefaultClaimsProvider>();
        services.TryAddScoped<IAccessTokenGenerator, AccessTokenGenerator>();
        services.TryAddScoped<IRefreshTokenGenerator, RefreshTokenGenerator>();
        services.TryAddScoped<ITokenGeneratorService, TokenGeneratorService>();
        services.TryAddScoped<IRefreshTokenValidator, RefreshTokenValidator>();
        services.TryAddScoped<ILoginService, JwtLoginService>();
        services.TryAddScoped<JwtLoginService>();
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
        var configureOptions = ConfigureJwtBearerOptions(sjOptions);

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(configureOptions)
                .AddJwtBearer("jwt", configureOptions);

        services.AddHttpContextAccessor();
        services.TryAddScoped<ILoginService, JwtHttpOnlyCookieLoginService>();
        services.TryAddScoped<JwtHttpOnlyCookieLoginService>();

        if (sjOptions.UseCookie)
        {
            services.AddHttpContextAccessor();
            services.TryAddScoped<ILoginService, JwtHttpOnlyCookieLoginService>();
            services.TryAddScoped<JwtHttpOnlyCookieLoginService>();

            var builder = AddSimpleJwtCore<TUser, TContext>(services, sjOptions);

            var jwtCookieEndpointsType = typeof(JwtCookieEndpointDefinitions<,>).MakeGenericType(builder.UserKeyType, builder.UserType);
            services.AddSingleton(typeof(IEndpointDefinition), jwtCookieEndpointsType);

            return builder;
        }

        var builder1 = AddSimpleJwtCore<TUser, TContext>(services, sjOptions);

        var endpointsType = typeof(JwtEndpointDefinition<,>).MakeGenericType(builder1.UserKeyType, builder1.UserType);
        services.AddSingleton(typeof(IEndpointDefinition), endpointsType);
        return builder1;
    }

    /// <summary>
    /// Adds the SimpleJwt default system
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="services"></param>
    /// <returns>An <see cref="SimpleJwtBuilder"/> for creating and configuring the SimpleJwt system.</returns>
    [Obsolete(message: "Please use AddSimpleJwtEndpoints(options) instead.")]
    public static SimpleJwtBuilder AddJwtCookieEndpoints<TUser, TContext>(this IServiceCollection services)
        where TUser : class
        where TContext : DbContext
    {
        return services.AddSimpleJwtEndpoints<TUser, TContext>(o => 
        {
            o.UseCookie = true;
        });
    }

    /// <summary>
    /// Adds and configures Jwt in HttpOnly Cookie system.
    /// </summary>
    /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
    /// <param name="services">The services available in the application.</param>
    /// <param name="setup">An action to configure the <see cref="SimpleJwtOptions"/>.</param>
    /// <returns>An <see cref="SimpleJwtBuilder"/> for creating and configuring the SimpleJwt system.</returns>
    [Obsolete(message: "Please use AddSimpleJwtEndpoints(options) instead.")]
    public static SimpleJwtBuilder AddJwtCookieEndpoints<TUser, TContext>(this IServiceCollection services, Action<SimpleJwtOptions> setup)
        where TUser : class
        where TContext : DbContext
    {
        return services.AddSimpleJwtEndpoints<TUser, TContext>(setup);
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
