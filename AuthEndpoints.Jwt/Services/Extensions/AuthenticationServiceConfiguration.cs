using AuthEndpoints.Jwt.Models;
using AuthEndpoints.Jwt.Models.Configurations;
using AuthEndpoints.Jwt.Services.Authenticators;
using AuthEndpoints.Jwt.Services.Repositories;
using AuthEndpoints.Jwt.Services.TokenGenerators;
using AuthEndpoints.Jwt.Services.TokenValidators;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthEndpoints.Jwt.Services.Extensions;

public static class AuthenticationServiceConfiguration
{
    public static void AddJwtEndpoints<TUserKey, TUser, TRefreshToken>(this IServiceCollection services, ConfigurationManager configurationManager)
        where TUserKey : IEquatable<TUserKey>
        where TUser : IdentityUser<TUserKey>
        where TRefreshToken : GenericRefreshToken<TUser, TUserKey>, new()
    {
        services.AddScoped(typeof(IRefreshTokenRepository<TUserKey, TRefreshToken>), typeof(DatabaseRefreshTokenRepository<TUserKey, TUser, TRefreshToken>));
        services.AddSingleton<IdentityErrorDescriber>();
        services.AddScoped<UserAuthenticator<TUserKey, TUser, TRefreshToken>>();
        services.AddSingleton<AccessTokenGenerator<TUserKey, TUser>>();
        services.AddSingleton<RefreshTokenGenerator<TUserKey, TUser>>();
        services.AddSingleton<ITokenValidator, RefreshTokenValidator>();

        var authConfig = new AuthenticationConfiguration();
        configurationManager.Bind("Authentication", authConfig);
        services.AddSingleton(authConfig);

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
        services.AddSingleton(refreshTokenValidationParameters);
        services.AddSingleton<JwtSecurityTokenHandler>();
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
            }; ;
        });
    }

    public static void AddJwtEndpoints<TUser, TRefreshToken>(this IServiceCollection services, ConfigurationManager configurationManager)
        where TUser : IdentityUser
        where TRefreshToken : GenericRefreshToken<TUser, string>, new()
    {
        services.AddScoped(typeof(IRefreshTokenRepository<string, TRefreshToken>), typeof(DatabaseRefreshTokenRepository<string, TUser, TRefreshToken>));
        services.AddSingleton<IdentityErrorDescriber>();
        services.AddScoped<UserAuthenticator<string, TUser, TRefreshToken>>();
        services.AddSingleton<AccessTokenGenerator<string, TUser>>();
        services.AddSingleton<RefreshTokenGenerator<string, TUser>>();
        services.AddSingleton<ITokenValidator, RefreshTokenValidator>();

        var authConfig = new AuthenticationConfiguration();
        configurationManager.Bind("Authentication", authConfig);
        services.AddSingleton(authConfig);

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
        services.AddSingleton(refreshTokenValidationParameters);
        services.AddSingleton<JwtSecurityTokenHandler>();
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
            }; ;
        });
    }
}
