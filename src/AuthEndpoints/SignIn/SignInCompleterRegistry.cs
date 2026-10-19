using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.SignIn;

internal sealed class SignInCompleterNameRegistration
{
    public SignInCompleterNameRegistration(string name, Type? userType)
    {
        Name = name;
        UserType = userType;
    }

    public string Name { get; }

    public Type? UserType { get; }
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

    public static void AddName(IServiceCollection services, string name, Type? userType)
    {
        if (services.Any(descriptor =>
                descriptor.ServiceType == typeof(SignInCompleterNameRegistration)
                && descriptor.ImplementationInstance is SignInCompleterNameRegistration existing
                && string.Equals(existing.Name, name, StringComparison.Ordinal)
                && existing.UserType == userType))
        {
            return;
        }

        services.AddSingleton(new SignInCompleterNameRegistration(name, userType));
    }

    public static bool Contains<TUser>(IServiceProvider services, string name)
        where TUser : class
    {
        return services.GetServices<SignInCompleterNameRegistration>()
            .Any(registration => AppliesTo<TUser>(registration, name));
    }

    public static bool MatchesAny(IServiceProvider services, string name)
    {
        return services.GetServices<SignInCompleterNameRegistration>()
            .Any(registration => string.Equals(registration.Name, name, StringComparison.Ordinal));
    }

    private static bool AppliesTo<TUser>(SignInCompleterNameRegistration registration, string name)
        where TUser : class
    {
        return string.Equals(registration.Name, name, StringComparison.Ordinal)
            && (registration.UserType is null || registration.UserType == typeof(TUser));
    }

    private static void TryAddOpenGeneric(IServiceCollection services, Type implementationType, string name)
    {
        var serviceType = typeof(ISignInCompleter<>);
        if (!services.Any(descriptor => descriptor.ServiceType == serviceType && Equals(descriptor.ServiceKey, name)))
        {
            services.AddKeyedScoped(serviceType, name, implementationType);
        }

        AddName(services, name, userType: null);
    }
}
