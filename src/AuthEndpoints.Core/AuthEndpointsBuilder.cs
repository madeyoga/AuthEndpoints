using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Core;

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
    /// Creates a new instance of <see cref="AuthEndpointsBuilder"/>.
    /// </summary>
    /// <param name="userType">The type to use for the users.</param>
    /// <param name="services">The <see cref="IServiceCollection"/> to attach to.</param>
    public AuthEndpointsBuilder(Type userKeyType, Type userType, IServiceCollection services)
    {
        UserKeyType = userKeyType;
        UserType = userType;
        Services = services;
    }

    protected AuthEndpointsBuilder AddScoped(Type serviceType, Type concreteType)
    {
        Services.AddScoped(serviceType, concreteType);
        return this;
    }

    /// <summary>
    /// Add endpoint definition
    /// </summary>
    /// <typeparam name="TEndpointDefinition"></typeparam>
    /// <param name="builder"></param>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddEndpointDefinition<TEndpointDefinition>()
        where TEndpointDefinition : IEndpointDefinition
    {
        Services.AddSingleton(typeof(IEndpointDefinition), typeof(TEndpointDefinition));
        return this;
    }

    /// <summary>
    /// Add endpoint definition
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="definitionType"></param>
    /// <returns>The current <see cref="AuthEndpointsBuilder"/> instance.</returns>
    public virtual AuthEndpointsBuilder AddEndpointDefinition(Type definitionType)
    {
        Services.AddSingleton(typeof(IEndpointDefinition), definitionType);
        return this;
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
}
