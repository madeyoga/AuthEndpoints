﻿using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.SimpleJwt;

/// <summary>
/// Helper functions for configuring SimpleJwt services.
/// </summary>
public class SimpleJwtBuilder
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
    /// Gets the <see cref="SimpleJwtOptions"/>
    /// </summary>
    /// <value>
    /// Gets the <see cref="SimpleJwtOptions"/>
    /// </value>
    public SimpleJwtOptions Options { get; }

    /// <summary>
    /// Creates a new instance of <see cref="SimpleJwtBuilder"/>.
    /// </summary>
    /// <param name="userType">The type to use for the users.</param>
    /// <param name="services">The <see cref="IServiceCollection"/> to attach to.</param>
    public SimpleJwtBuilder(Type userKeyType, Type userType, IServiceCollection services, SimpleJwtOptions options)
    {
        UserKeyType = userKeyType;
        UserType = userType;
        Services = services;
        Options = options;
    }

    protected SimpleJwtBuilder AddScoped(Type serviceType, Type concreteType)
    {
        Services.AddScoped(serviceType, concreteType);
        return this;
    }

    /// <summary>
    /// Adds an <see cref="IAccessTokenGenerator"/>.
    /// </summary>
    /// <typeparam name="TGenerator">The type of the access token generator.</typeparam>
    /// <returns>The current <see cref="SimpleJwtBuilder"/> instance.</returns>
    public virtual SimpleJwtBuilder AddAccessTokenGenerator<TGenerator>() where TGenerator : class
    {
        return AddScoped(typeof(IAccessTokenGenerator), typeof(TGenerator));
    }

    /// <summary>
    /// Adds an <see cref="IAccessTokenGenerator"/>.
    /// </summary>
    /// <typeparam name="TGenerator">The type of the access token generator.</typeparam>
    /// <returns>The current <see cref="SimpleJwtBuilder"/> instance.</returns>
    public virtual SimpleJwtBuilder AddRefreshTokenGenerator<TGenerator>() where TGenerator : class
    {
        return AddScoped(typeof(IRefreshTokenService), typeof(TGenerator));
    }

    /// <summary>
    /// Adds an <see cref="IdentityErrorDescriber"/>.
    /// </summary>
    /// <typeparam name="TDescriber">The type of the error describer.</typeparam>
    /// <returns>The current <see cref="SimpleJwtBuilder"/> instance.</returns>
    public virtual SimpleJwtBuilder AddErrorDescriber<TDescriber>() where TDescriber : IdentityErrorDescriber
    {
        Services.AddScoped<IdentityErrorDescriber, TDescriber>();
        return this;
    }

    public virtual SimpleJwtBuilder AddRefreshTokenStore<TContext>() where TContext : DbContext
    {
        Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository<TContext>>();
        return this;
    }
}
