﻿using AuthEndpoints.Models.Responses;
using AuthEndpoints.Options;
using AuthEndpoints.Services.Authenticators;
using AuthEndpoints.Services.Claims;
using AuthEndpoints.Services.TokenGenerators;
using AuthEndpoints.Services.TokenValidators;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.IdentityModel.Tokens.Jwt;

namespace AuthEndpoints.Extensions;

/// <summary>
/// Provides extensions to easily bootstrap authendpoints
/// </summary>
public static class ServiceCollectionExtensions
{
    internal static AuthEndpointsBuilder ConfigureServices<TUserKey, TUser>(IServiceCollection services)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        services.TryAddSingleton<IClaimsProvider<TUser>, DefaultClaimsProvider<TUserKey, TUser>>();
        services.TryAddScoped<IAccessTokenGenerator<TUser>, AccessTokenGenerator<TUser>>();
        services.TryAddScoped<IRefreshTokenGenerator<TUser>, RefreshTokenGenerator<TUser>>();
        services.TryAddScoped<ITokenValidator, RefreshTokenValidator>();
        services.TryAddScoped<IAuthenticator<TUser, AuthenticatedJwtResponse>, JwtUserAuthenticator<TUser>>();

        services.TryAddScoped<IdentityErrorDescriber>();
        services.TryAddSingleton<JwtSecurityTokenHandler>();

        return new AuthEndpointsBuilder(typeof(TUser), services);
    }

    public static AuthEndpointsBuilder AddAuthEndpoints<TUserKey, TUser>(this IServiceCollection services)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        services.AddOptions<AuthEndpointsOptions>();
        return services.AddAuthEndpoints<TUserKey, TUser>(o => { });
    }

    /// <summary>
    /// Adds and configures the authendpoints system for the specified User type.
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
        if (setup != null)
        {
            services.Configure(setup);
        }

        return ConfigureServices<TUserKey, TUser>(services);
    }

    public static AuthEndpointsBuilder AddAuthEndpoints<TUserKey, TUser>(this IServiceCollection services, AuthEndpointsOptions customOptions)
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
            options.AccessTokenValidationParameters = customOptions.AccessTokenValidationParameters;
            options.RefreshTokenValidationParameters = customOptions.RefreshTokenValidationParameters;
        });
        return ConfigureServices<TUserKey, TUser>(services);
    }
}