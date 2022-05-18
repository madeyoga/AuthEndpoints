using AuthEndpoints.Models;
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
    /// Gets the <see cref="Type"/> used for users.
    /// </summary>
    /// <value>
    /// The <see cref="Type"/> used for users.
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
    /// Creates a new instance of <see cref="AuthEndpointsBuilder"/>.
    /// </summary>
    /// <param name="userType">The <see cref="Type"/> to use for the users.</param>
    /// <param name="services">The <see cref="IServiceCollection"/> to attach to.</param>
    public AuthEndpointsBuilder(Type userType, IServiceCollection services)
    {
        UserType = userType;
        Services = services;
    }

    protected AuthEndpointsBuilder AddScoped(Type serviceType, Type concreteType)
    {
        Services.AddScoped(serviceType, concreteType);
        return this;
    }

    /// <summary>
    /// Adds an <see cref="IAccessTokenClaimsProvider{TUser}"/>.
    /// </summary>
    /// <typeparam name="TProvider">The type of the claims provider.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddAccessTokenClaimsProvider<TProvider>() where TProvider : class
    {
        return AddScoped(typeof(IAccessTokenClaimsProvider<>).MakeGenericType(UserType), typeof(TProvider));
    }

    /// <summary>
    /// Adds an <see cref="IRefreshTokenClaimsProvider{TUser}"/>.
    /// </summary>
    /// <typeparam name="TProvider">The type of the claims provider.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddRefreshTokenClaimsProvider<TProvider>() where TProvider : class
    {
        return AddScoped(typeof(IRefreshTokenClaimsProvider<>).MakeGenericType(UserType), typeof(TProvider));
    }

    /// <summary>
    /// Adds an <see cref="IAccessTokenGenerator{TUser}"/>.
    /// </summary>
    /// <typeparam name="TGenerator">The type of the token generator.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddAccessTokenGenerator<TGenerator>() where TGenerator : class
    {
        return AddScoped(typeof(IAccessTokenGenerator<>).MakeGenericType(UserType), typeof(TGenerator));
    }

    /// <summary>
    /// Adds an <see cref="IRefreshTokenGenerator{TUser}"/>.
    /// </summary>
    /// <typeparam name="TGenerator">The type of the token generator.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddRefreshTokenGenerator<TGenerator>() where TGenerator : class
    {
        return AddScoped(typeof(IRefreshTokenGenerator<>).MakeGenericType(UserType), typeof(TGenerator));
    }

    /// <summary>
    /// Adds an <see cref="ITokenValidator"/>.
    /// </summary>
    /// <typeparam name="TValidator">The type of the token validator.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddRefreshTokenValidator<TValidator>() where TValidator : ITokenValidator
    {
        return AddScoped(typeof(ITokenValidator), typeof(TValidator));
    }

    /// <summary>
    /// Adds an <see cref="IAuthenticator{TUser}"/>.
    /// </summary>
    /// <typeparam name="TAuthenticator">The type of the token validator.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddUserAuthenticator<TAuthenticator>() where TAuthenticator : class
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
    /// Adds a jwt bearer defaults authentication scheme.
    /// </summary>
    /// <param name="parameters">Token validation parameters for JwtBearerOptions</param>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddJwtBearerAuthenticationScheme(TokenValidationParameters parameters)
    {
        Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(option =>
        {
            option.TokenValidationParameters = parameters;
        });
        return this;
    }
}
