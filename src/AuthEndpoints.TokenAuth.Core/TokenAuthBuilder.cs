using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.TokenAuth.Core;

public class TokenAuthBuilder
{
    public TokenAuthBuilder(Type keyType, Type userType, Type contextType, IServiceCollection services)
    {
        KeyType = keyType;
        UserType = userType;
        ContextType = contextType;
        Services = services;
    }

    public Type KeyType { get; set; }
    public Type UserType { get; set; }
    public Type ContextType { get; set; }
    public IServiceCollection Services { get; set; }
}
