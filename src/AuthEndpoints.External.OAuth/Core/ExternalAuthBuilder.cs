using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.External.OAuth;

/// <summary>
/// Fluent helper for configuring external auth providers and the login completer.
/// </summary>
public sealed class ExternalAuthBuilder
{
    public ExternalAuthBuilder(Type userType, IServiceCollection services)
    {
        UserType = userType;
        Services = services;
    }

    public Type UserType { get; }

    public IServiceCollection Services { get; }

    /// <summary>
    /// Replaces the default <see cref="IExternalLoginCompleter{TUser}"/> registration.
    /// </summary>
    public ExternalAuthBuilder AddCompleter<TCompleter>()
        where TCompleter : class
    {
        var completerType = typeof(IExternalLoginCompleter<>).MakeGenericType(UserType);
        Services.AddScoped(completerType, typeof(TCompleter));
        return this;
    }

    /// <summary>
    /// Registers an <see cref="IExternalAuthProvider"/> singleton.
    /// </summary>
    public ExternalAuthBuilder AddProvider<TProvider>()
        where TProvider : class, IExternalAuthProvider
    {
        Services.AddSingleton<IExternalAuthProvider, TProvider>();
        return this;
    }

    /// <summary>
    /// Registers an <see cref="IExternalAuthProvider"/> instance.
    /// </summary>
    public ExternalAuthBuilder AddProvider(IExternalAuthProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        Services.AddSingleton(provider);
        return this;
    }
}
