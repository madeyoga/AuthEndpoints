using System.IdentityModel.Tokens.Jwt;
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

        services.TryAddScoped<IAuthenticator<TUser>, DefaultAuthenticator<TUser>>();
        services.TryAddScoped<IAccessTokenGenerator, AccessTokenGenerator>();
        services.TryAddScoped<IRefreshTokenService, RefreshTokenService<TContext>>();
        services.TryAddScoped<RefreshTokenCookieWriter>();
        services.TryAddScoped<IdentityErrorDescriber>();
        services.TryAddScoped<JwtSecurityTokenHandler>();

        return new SimpleJwtBuilder(identityUserType, typeof(TUser), services, options);
    }

    /// <summary>
    /// Adds the Jwt default system
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="services"></param>
    /// <returns>An <see cref="JwtBuilder"/> for creating and configuring the Jwt system.</returns>
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
                jwtSetup?.Invoke(options); // optional advanced customization
            });

        var builder1 = AddSimpleJwtCore<TUser, TContext>(services, sjOptions);

        return builder1;
    }
}
