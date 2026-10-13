using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.SignIn;

internal sealed class SignInCompleterNameRegistration
{
    public SignInCompleterNameRegistration(string name)
    {
        Name = name;
    }

    public string Name { get; }
}

internal static class SignInCompleterRegistry
{
    public static void AddIdentityCompleters(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        TryAddOpenGeneric(services, typeof(CookieSignInCompleter<>), SignInCompleters.Cookie);
        TryAddOpenGeneric(services, typeof(IdentityBearerSignInCompleter<>), SignInCompleters.IdentityBearer);
        services.AddOptions<SignInCompletionOptions>();
    }

    public static void AddJwtCompleter(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        TryAddOpenGeneric(services, typeof(JwtSignInCompleter<>), SignInCompleters.Jwt);
        services.AddOptions<SignInCompletionOptions>();
    }

    public static void AddName(IServiceCollection services, string name)
    {
        if (services.Any(descriptor =>
                descriptor.ServiceType == typeof(SignInCompleterNameRegistration)
                && descriptor.ImplementationInstance is SignInCompleterNameRegistration existing
                && string.Equals(existing.Name, name, StringComparison.Ordinal)))
        {
            return;
        }

        services.AddSingleton(new SignInCompleterNameRegistration(name));
    }

    public static bool Contains(IServiceProvider services, string name)
    {
        return services.GetServices<SignInCompleterNameRegistration>()
            .Any(registration => string.Equals(registration.Name, name, StringComparison.Ordinal));
    }

    private static void TryAddOpenGeneric(IServiceCollection services, Type implementationType, string name)
    {
        var serviceType = typeof(ISignInCompleter<>);
        if (!services.Any(descriptor => descriptor.ServiceType == serviceType && Equals(descriptor.ServiceKey, name)))
        {
            services.AddKeyedScoped(serviceType, name, implementationType);
        }

        AddName(services, name);
    }
}
