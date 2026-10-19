using AuthEndpoints.SignIn;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints;

public static class SignInCompleterServiceCollectionExtensions
{
    /// <summary>
    /// Registers <typeparamref name="TCompleter"/> as a keyed <see cref="ISignInCompleter{TUser}"/> under <paramref name="name"/>.
    /// Safe to call twice for the same user and name: the later registration wins.
    /// </summary>
    public static IServiceCollection AddSignInCompleter<TUser, TCompleter>(this IServiceCollection services, string name)
        where TUser : class
        where TCompleter : class, ISignInCompleter<TUser>
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var serviceType = typeof(ISignInCompleter<TUser>);
        for (var i = services.Count - 1; i >= 0; i--)
        {
            var descriptor = services[i];
            if (descriptor.ServiceType == serviceType && Equals(descriptor.ServiceKey, name))
            {
                services.RemoveAt(i);
            }
        }

        services.AddKeyedScoped<ISignInCompleter<TUser>, TCompleter>(name);
        SignInCompleterRegistry.AddName(services, name, typeof(TUser));
        return services;
    }
}
