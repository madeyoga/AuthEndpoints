using AuthEndpoints.Jwt;
using AuthEndpoints.SignIn;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

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

    /// <summary>
    /// Replaces the default <see cref="IExternalLoginCompleter{TUser}"/> registration.
    /// </summary>
    [Obsolete(LegacyCompleterMessages.Obsolete)]
    public ExternalAuthBuilder AddCompleter<TCompleter>()
        where TCompleter : class
    {
        var completerType = typeof(IExternalLoginCompleter<>).MakeGenericType(UserType);
        if (!completerType.IsAssignableFrom(typeof(TCompleter)))
        {
            throw new InvalidOperationException(
                $"{typeof(TCompleter).Name} does not implement {completerType.Name}.");
        }

        for (var i = Services.Count - 1; i >= 0; i--)
        {
            if (Services[i].ServiceType == completerType)
            {
                Services.RemoveAt(i);
            }
        }

        Services.AddScoped(completerType, typeof(TCompleter));
        LegacySignInCompleters.MarkExternal(Services, UserType);
        if (typeof(TCompleter).IsGenericType
            && typeof(TCompleter).GetGenericTypeDefinition() == typeof(JwtExternalLoginCompleter<>))
        {
            Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IValidateOptions<JwtSessionOptions>, JwtExternalBodyTransportValidator>());
        }

        return this;
    }

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
