using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Jwt;

public class SimpleJwtBuilder
{
    public Type UserKeyType { get; }

    public Type UserType { get; }

    public IServiceCollection Services { get; }

    public SimpleJwtOptions Options { get; }

    public SimpleJwtBuilder(Type keyType, Type userType, IServiceCollection services, SimpleJwtOptions options)
    {
        UserKeyType = keyType;
        UserType = userType;
        Services = services;
        Options = options;
    }

    protected SimpleJwtBuilder AddScoped(Type serviceType, Type concreteType)
    {
        Services.AddScoped(serviceType, concreteType);
        return this;
    }

    public virtual SimpleJwtBuilder AddAccessTokenGenerator<TGenerator>() where TGenerator : class
    {
        return AddScoped(typeof(IAccessTokenGenerator), typeof(TGenerator));
    }

    public virtual SimpleJwtBuilder AddRefreshTokenService<TService>() where TService : class
    {
        return AddScoped(typeof(IRefreshTokenService), typeof(TService));
    }

    public virtual SimpleJwtBuilder AddErrorDescriber<TDescriber>() where TDescriber : IdentityErrorDescriber
    {
        Services.AddScoped<IdentityErrorDescriber, TDescriber>();
        return this;
    }
}
