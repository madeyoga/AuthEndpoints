using AuthEndpoints.Models.Responses;
using AuthEndpoints.Services.Authenticators;
using AuthEndpoints.Services.Claims;
using AuthEndpoints.Services.TokenGenerators;
using AuthEndpoints.Services.TokenValidators;
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
    public Type UserType { get; private set; }

    /// <summary>
    /// Gets the <see cref="IServiceCollection"/> services are attached to.
    /// </summary>
    /// <value>
    /// The <see cref="IServiceCollection"/> services are attached to.
    /// </value>
    public IServiceCollection Services { get; private set; }

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

    private AuthEndpointsBuilder AddScoped(Type serviceType, Type concreteType)
    {
        Services.AddScoped(serviceType, concreteType);
        return this;
    }

    /// <summary>
    /// Adds a <see cref="IClaimsProvider{TUser}"/>.
    /// </summary>
    /// <typeparam name="TProvider">The type of the claims provider.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddClaimsProvider<TProvider>() where TProvider : class
    {
        return AddScoped(typeof(IClaimsProvider<>).MakeGenericType(UserType), typeof(TProvider));
    }

    /// <summary>
    /// Adds a <see cref="IAccessTokenGenerator{TUser}"/>.
    /// </summary>
    /// <typeparam name="TGenerator">The type of the token generator.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddAccessTokenGenerator<TGenerator>() where TGenerator : class
    {
        return AddScoped(typeof(IAccessTokenGenerator<>).MakeGenericType(UserType), typeof(TGenerator));
    }

    /// <summary>
    /// Adds a <see cref="IRefreshTokenGenerator{TUser}"/>.
    /// </summary>
    /// <typeparam name="TGenerator">The type of the token generator.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddRefreshTokenGenerator<TGenerator>() where TGenerator : class
    {
        return AddScoped(typeof(IRefreshTokenGenerator<>).MakeGenericType(UserType), typeof(TGenerator));
    }

    /// <summary>
    /// Adds a <see cref="ITokenValidator"/>.
    /// </summary>
    /// <typeparam name="TValidator">The type of the token validator.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddTokenValidator<TValidator>() where TValidator : class
    {
        return AddScoped(typeof(ITokenValidator), typeof(TValidator));
    }

    /// <summary>
    /// Adds a <see cref="IAuthenticator{TUser, TResponse}"/>.
    /// </summary>
    /// <typeparam name="TAuthenticator">The type of the token validator.</typeparam>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddUserAuthenticator<TAuthenticator>() where TAuthenticator : class
    {
        return AddScoped(typeof(IAuthenticator<,>).MakeGenericType(UserType, typeof(AuthenticatedJwtResponse)), typeof(TAuthenticator));
    }

    /// <summary>
    /// Adds an <see cref="IdentityErrorDescriber"/>.
    /// </summary>
    /// <typeparam name="TDescriber">The type of the error describer.</typeparam>
    /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddErrorDescriber<TDescriber>() where TDescriber : IdentityErrorDescriber
    {
        Services.AddScoped<IdentityErrorDescriber, TDescriber>();
        return this;
    }

    /// <summary>
    /// Adds a jwt bearer defaults authentication scheme.
    /// </summary>
    /// <typeparam name="TDescriber">The type of the error describer.</typeparam>
    /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddJwtBearerAuthenticationScheme(TokenValidationParameters parameters)
    {
        Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(option =>
        {
            option.TokenValidationParameters = parameters;
        });
        return this;
    }
}
