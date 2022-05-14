using AuthEndpoints.Options;
using AuthEndpoints.Services.Authenticators;
using AuthEndpoints.Services.Claims;
using AuthEndpoints.Services.TokenGenerators;
using AuthEndpoints.Services.TokenValidators;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthEndpoints.Extensions;

/// <summary>
/// Provides extensions to easily bootstrap authendpoints
/// </summary>
public static class ServiceExtensions
{
    private static IServiceCollection Configure<TUserKey, TUser>(IServiceCollection services, AuthEndpointsOptions options)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        var refreshTokenValidationParameters = new TokenValidationParameters()
        {
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.RefreshTokenSecret!)),
            ValidIssuer = options.Issuer,
            ValidAudience = options.Audience,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ClockSkew = TimeSpan.Zero,
        };
        services.TryAddSingleton(refreshTokenValidationParameters);
        services.TryAddSingleton<IdentityErrorDescriber>();
        services.TryAddSingleton<JwtSecurityTokenHandler>();
        services.TryAddSingleton<IClaimsProvider<TUser>, DefaultClaimsProvider<TUserKey, TUser>>();
        services.TryAddScoped<JwtUserAuthenticator<TUser>>();
        services.TryAddSingleton<AccessJwtGenerator<TUser>>();
        services.TryAddSingleton<RefreshTokenGenerator<TUser>>();
        services.TryAddSingleton<ITokenValidator, RefreshTokenValidator>();
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(option =>
        {
            option.TokenValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.AccessTokenSecret!)),
                ValidIssuer = options.Issuer,
                ValidAudience = options.Audience,
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ClockSkew = TimeSpan.Zero,
            };
        });

        return services;
    }

    public static IServiceCollection AddAuthEndpoints<TUserKey, TUser>(this IServiceCollection services)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        var options = new AuthEndpointsOptions()
        {
            AccessTokenSecret = "9GHdZCAJ2XaXFuhOhIt21zxJCWk7obnzcHqDB4t7X0WcvrB8bzvkyEFlIMRXO4o-y3eQs8e4uDiFJcAhnFOiE6I45aJQi22DEy5epVLyQIVFYI-dbumj8ieK1sKMPySfN9S4eliQznJYL82XhtI_8U1EvEL2_C7PX4rTR0Xjf8k",
            RefreshTokenSecret = "8GHdZCAJ2XaXFuhOhIt21zxJCWk7obnzcHqDB4t7X0WcvrB8bzvkyEFlIMRXO4o-y3eQs8e4uDiFJcAhnFOiE6I45aJQi22DEy5epVLyQIVFYI-dbumj8ieK1sKMPySfN9S4eliQznJYL82XhtI_8U1EvEL2_C7PX4rTR0Xjf8k",
            AccessTokenExpirationMinutes = 15,
            RefreshTokenExpirationMinutes = 6000,
            Audience = "https://localhost:8000",
            Issuer = "https://localhost:8000"
        };
        services.AddSingleton(options);
        return Configure<TUserKey, TUser>(services, options);
    }

    public static IServiceCollection AddAuthEndpoints<TUserKey, TUser>(this IServiceCollection services, Action<AuthEndpointsOptions> configureOptions)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        var options = new AuthEndpointsOptions();
        configureOptions.Invoke(options);
        services.Configure(configureOptions);
        return Configure<TUserKey, TUser>(services, options);
    }

    public static IServiceCollection AddAuthEndpoints<TUserKey, TUser>(this IServiceCollection services, AuthEndpointsOptions customOptions)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        services.AddOptions<AuthEndpointsOptions>().Configure(options =>
        {
            options.AccessTokenSecret = customOptions.AccessTokenSecret;
            options.RefreshTokenSecret = customOptions.RefreshTokenSecret;
            options.AccessTokenExpirationMinutes = customOptions.AccessTokenExpirationMinutes;
            options.RefreshTokenExpirationMinutes = customOptions.RefreshTokenExpirationMinutes;
            options.Audience = customOptions.Audience;
            options.Issuer = customOptions.Issuer;
        });

        return Configure<TUserKey, TUser>(services, customOptions);
    }

    public static IServiceCollection AddAuthEndpoints<TUserKey, TUser>(this IServiceCollection services, IConfiguration configuration)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        var customOptions = new AuthEndpointsOptions();
        configuration.Bind("AuthEndpointsOptions", customOptions);
        services.AddSingleton(customOptions);
        return Configure<TUserKey, TUser>(services, customOptions);
    }
}
