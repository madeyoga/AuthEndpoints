using AuthEndpoints.Models.Configurations;
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
public static class AuthEndpointsServiceExtension
{
    private static void Configure<TUserKey, TUser>(IServiceCollection services, ConfigurationManager configurationManager)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        var authConfig = new AuthenticationConfiguration();
        configurationManager.Bind("AuthEndpoints", authConfig);
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

    public static void AddAuthEndpoints<TUserKey, TUser>(this IServiceCollection services, ConfigurationManager configurationManager)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
    {
        Configure<TUserKey, TUser>(services, configurationManager);
    }

    public static void AddAuthEndpoints<TUser>(this IServiceCollection services, ConfigurationManager configurationManager)
        where TUser : IdentityUser
    {
        Configure<string, TUser>(services, configurationManager);
    }
}
