using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.External.OAuth;

public sealed class ExternalAuthBuilder
{
    public ExternalAuthBuilder(Type userType, IServiceCollection services)
    {
        UserType = userType;
        Services = services;
    }

    public Type UserType { get; }

    public IServiceCollection Services { get; }

    public ExternalAuthBuilder AddProvider<TProvider>()
        where TProvider : class, IExternalAuthProvider
    {
        Services.AddSingleton<IExternalAuthProvider, TProvider>();
        return this;
    }

    public ExternalAuthBuilder AddProvider(IExternalAuthProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        Services.AddSingleton(provider);
        return this;
    }
}
