using AuthEndpoints.Controllers;
using AuthEndpoints.Models;
using AuthEndpoints.Models.Configurations;
using AuthEndpoints.Services.Authenticators;
using AuthEndpoints.Services.Providers;
using AuthEndpoints.Services.Repositories;
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

public static class AuthEndpointsServiceExtension
{
    private static void Configure<TUserKey, TUser, TRefreshToken>(IServiceCollection services, ConfigurationManager configurationManager)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
        where TRefreshToken : GenericRefreshToken<TUser, TUserKey>, new()
    {
        var authConfig = new AuthenticationConfiguration();
        configurationManager.Bind("Authentication", authConfig);
        var refreshTokenValidationParameters = new TokenValidationParameters()
        {
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authConfig.RefreshTokenSecret!)),
            ValidIssuer = authConfig.Issuer,
            ValidAudience = authConfig.Audience,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ClockSkew = TimeSpan.Zero,
        };
        services.TryAddSingleton(authConfig);
        services.TryAddSingleton(refreshTokenValidationParameters);
        services.TryAddSingleton(typeof(IClaimsProvider<TUser>), typeof(DefaultClaimsProvider<TUserKey, TUser>));
        services.TryAddScoped(typeof(IRefreshTokenRepository<TUserKey, TRefreshToken>), typeof(DatabaseRefreshTokenRepository<TUserKey, TUser, TRefreshToken>));
        services.TryAddSingleton<IdentityErrorDescriber>();
        services.TryAddScoped<JwtUserAuthenticator<TUserKey, TUser, TRefreshToken>>();
        services.TryAddSingleton<AccessJwtGenerator<TUserKey, TUser>>();
        services.TryAddSingleton<RefreshTokenGenerator<TUserKey, TUser>>();
        services.TryAddSingleton<ITokenValidator, RefreshTokenValidator>();
        services.TryAddSingleton<JwtSecurityTokenHandler>();
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(option =>
        {
            option.TokenValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authConfig.AccessTokenSecret!)),
                ValidIssuer = authConfig.Issuer,
                ValidAudience = authConfig.Audience,
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ClockSkew = TimeSpan.Zero,
            };
        });
    }

    public static void AddAuthEndpoints<TUserKey, TUser, TRefreshToken>(this IServiceCollection services, ConfigurationManager configurationManager)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
        where TRefreshToken : GenericRefreshToken<TUser, TUserKey>, new()
    {
        Configure<TUserKey, TUser, TRefreshToken>(services, configurationManager);
    }

    public static void AddAuthEndpoints<TUser, TRefreshToken>(this IServiceCollection services, ConfigurationManager configurationManager)
        where TUser : IdentityUser
        where TRefreshToken : GenericRefreshToken<TUser, string>, new()
    {
        Configure<string, TUser, TRefreshToken>(services, configurationManager);
    }
}
