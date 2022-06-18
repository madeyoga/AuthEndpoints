using AuthEndpoints.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints;

/// <summary>
/// Helper functions for configuring AuthEndpoints services.
/// </summary>
public class AuthEndpointsBuilder
{
    /// <summary>
    /// Gets the type used for user id.
    /// </summary>
    /// <value>
    /// The type used for user id.
    /// </value>
    public Type UserKeyType { get; }

    /// <summary>
    /// Gets the type used for users.
    /// </summary>
    /// <value>
    /// The type used for users.
    /// </value>
    public Type UserType { get; }

    /// <summary>
    /// Gets the <see cref="IServiceCollection"/> services are attached to.
    /// </summary>
    /// <value>
    /// The <see cref="IServiceCollection"/> services are attached to.
    /// </value>
    public IServiceCollection Services { get; }

    /// <summary>
    /// Gets the <see cref="AuthEndpointsOptions"/>
    /// </summary>
    /// <value>
    /// Gets the <see cref="AuthEndpointsOptions"/>
    /// </value>
    public AuthEndpointsOptions Options { get; }

    /// <summary>
    /// Creates a new instance of <see cref="AuthEndpointsBuilder"/>.
    /// </summary>
    /// <param name="userType">The type to use for the users.</param>
    /// <param name="services">The <see cref="IServiceCollection"/> to attach to.</param>
    public AuthEndpointsBuilder(Type userKeyType, Type userType, IServiceCollection services, AuthEndpointsOptions options)
    {
        UserKeyType = userKeyType;
        UserType = userType;
        Services = services;
        Options = options;
    }

    protected AuthEndpointsBuilder AddScoped(Type serviceType, Type concreteType)
    {
        Services.AddScoped(serviceType, concreteType);
        return this;
    }

    /// <summary>
    /// Adds an <see cref="IClaimsProvider{TUser}"/>.
    /// </summary>
    /// <typeparam name="TProvider">The type of the claims provider.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddClaimsProvider<TProvider>() where TProvider : class
    {
        return AddScoped(typeof(IClaimsProvider<>).MakeGenericType(UserType), typeof(TProvider));
    }

    /// <summary>
    /// Adds an <see cref="IJwtFactory"/>.
    /// </summary>
    /// <typeparam name="TGenerator">The type of the jwt factory.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddJwtFactory<TGenerator>() where TGenerator : IJwtFactory
    {
        return AddScoped(typeof(IJwtFactory), typeof(TGenerator));
    }

    /// <summary>
    /// Adds an <see cref="IJwtValidator"/>
    /// </summary>
    /// <typeparam name="TValidator">The type of the jwt validator</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddJwtValidator<TValidator>() where TValidator : IJwtValidator
    {
        return AddScoped(typeof(IJwtValidator), typeof(TValidator));
    }

    /// <summary>
    /// Adds an <see cref="IAuthenticator{TUser}"/>.
    /// </summary>
    /// <typeparam name="TAuthenticator">The type of the authenticator.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddAuthenticator<TAuthenticator>() where TAuthenticator : class
    {
        return AddScoped(typeof(IAuthenticator<>).MakeGenericType(UserType), typeof(TAuthenticator));
    }

    /// <summary>
    /// Adds an <see cref="IdentityErrorDescriber"/>.
    /// </summary>
    /// <typeparam name="TDescriber">The type of the error describer.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddErrorDescriber<TDescriber>() where TDescriber : IdentityErrorDescriber
    {
        Services.AddScoped<IdentityErrorDescriber, TDescriber>();
        return this;
    }

    /// <summary>
    /// Adds an <see cref="IEmailFactory"/>
    /// </summary>
    /// <typeparam name="TEmailFactory"></typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddEmailFactory<TEmailFactory>() where TEmailFactory : IEmailFactory
    {
        Services.AddSingleton(typeof(IEmailFactory), typeof(TEmailFactory));
        return this;
    }

    /// <summary>
    /// Adds an <see cref="IEmailSender"/>
    /// </summary>
    /// <typeparam name="TEmailFactory"></typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddEmailSender<TSender>() where TSender : IEmailSender
    {
        Services.AddSingleton(typeof(IEmailFactory), typeof(TSender));
        return this;
    }

    /// <summary>
    /// Adds a jwt bearer defaults authentication scheme.
    /// </summary>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddJwtBearerAuthScheme()
    {
        if (Options.AccessValidationParameters == null)
        {
            Options.AccessValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = Options.AccessSigningOptions.SigningKey,
                ValidIssuer = Options.Issuer,
                ValidAudience = Options.Audience,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero,
            };
        }
        
        Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer("jwt", options =>
            {
                options.TokenValidationParameters = Options.AccessValidationParameters!;
            });
        return this;
    }

    /// <summary>
    /// Adds a jwt bearer defaults authentication scheme.
    /// </summary>
    /// <param name="parameters">Token validation parameters for JwtBearerOptions</param>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddJwtBearerAuthScheme(TokenValidationParameters parameters)
    {
        Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer("jwt", options =>
            {
                options.TokenValidationParameters = parameters;
            });
        return this;
    }
}
