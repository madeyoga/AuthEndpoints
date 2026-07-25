using System.IdentityModel.Tokens.Jwt;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Jwt;

public static class ServiceCollectionExtensions
{
    private static SimpleJwtBuilder AddSimpleJwtCore<TUser, TContext>(this IServiceCollection services, SimpleJwtOptions options)
        where TUser : class
        where TContext : DbContext
    {
        var identityUserType = TypeHelper.FindGenericBaseType(typeof(TUser), typeof(IdentityUser<>))
            ?? throw new InvalidOperationException("Generic type TUser is not IdentityUser");

        services.AddSingleton(Options.Create(options));
        services.AddOptions<SimpleJwtOptions>()
            .Configure(o =>
            {
                o.Issuer = options.Issuer;
                o.Audience = options.Audience;
                o.AccessTokenLifetime = options.AccessTokenLifetime;
                o.SigningOptions = options.SigningOptions;
                o.TokenValidationParameters = options.TokenValidationParameters;
            })
            .ValidateOnStart();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<SimpleJwtOptions>, SimpleJwtOptionsValidator>());

        services.TryAddScoped<IAuthenticator<TUser>, DefaultAuthenticator<TUser>>();
        services.TryAddScoped<IAccessTokenGenerator, AccessTokenGenerator>();
        services.TryAddScoped<IRefreshTokenService, RefreshTokenService<TContext>>();
        services.TryAddScoped<RefreshTokenCookieWriter>();
        services.TryAddScoped<IdentityErrorDescriber>();
        services.TryAddScoped<JwtSecurityTokenHandler>();

        services.AddIdentityEndpointRateLimiting();

        return new SimpleJwtBuilder(identityUserType, typeof(TUser), services, options);
    }

    /// <summary>
    /// Adds the Jwt default system
    /// </summary>
    public static SimpleJwtBuilder AddJwtEndpoints<TUser, TContext>(this IServiceCollection services)
        where TUser : class
        where TContext : DbContext
    {
        return services.AddJwtEndpoints<TUser, TContext>(o => { }, o => { });
    }

    public static SimpleJwtBuilder AddJwtEndpoints<TUser, TContext>(
        this IServiceCollection services,
        Action<SimpleJwtOptions> setup,
        Action<JwtBearerOptions>? jwtSetup = null)
        where TUser : class
        where TContext : DbContext
    {
        var sjOptions = new SimpleJwtOptions();
        setup(sjOptions);

        var validationResult = new SimpleJwtOptionsValidator().Validate(nameof(SimpleJwtOptions), sjOptions);
        if (validationResult is { Succeeded: false })
            throw new OptionsValidationException(nameof(SimpleJwtOptions), typeof(SimpleJwtOptions), validationResult.Failures);

        var validationParams = sjOptions.TokenValidationParameters ?? new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = sjOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = sjOptions.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = sjOptions.SigningOptions.ToSecurityKey()
        };

        services.AddAuthentication()
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters = validationParams;
                jwtSetup?.Invoke(options);
            });

        return AddSimpleJwtCore<TUser, TContext>(services, sjOptions);
    }
}
