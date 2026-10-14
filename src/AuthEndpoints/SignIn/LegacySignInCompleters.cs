using AuthEndpoints.EmailCode;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.Passkey;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthEndpoints.SignIn;

internal sealed class ExplicitEmailCodeSignInCompleterMarker<TUser>
    where TUser : class;

internal sealed class ExplicitPasskeySignInCompleterMarker<TUser>
    where TUser : class;

internal sealed class ExplicitExternalLoginCompleterMarker
{
    public ExplicitExternalLoginCompleterMarker(Type userType)
    {
        UserType = userType;
    }

    public Type UserType { get; }
}

internal static class LegacySignInCompleters
{
    public static void MarkEmailCode<TUser>(IServiceCollection services)
        where TUser : class
    {
        services.TryAddSingleton<ExplicitEmailCodeSignInCompleterMarker<TUser>>();
    }

    public static void MarkPasskey<TUser>(IServiceCollection services)
        where TUser : class
    {
        services.TryAddSingleton<ExplicitPasskeySignInCompleterMarker<TUser>>();
    }

    public static void MarkExternal(IServiceCollection services, Type userType)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(userType);
        services.AddSingleton(new ExplicitExternalLoginCompleterMarker(userType));
    }

    public static bool EmailCodeWins<TUser>(IServiceProvider services)
        where TUser : class
    {
        if (services.GetService<ExplicitEmailCodeSignInCompleterMarker<TUser>>() is not null)
        {
            return true;
        }

        using var scope = services.CreateScope();
        var completer = scope.ServiceProvider.GetService<IEmailCodeSignInCompleter<TUser>>();
        return completer is not null && completer is not IdentityEmailCodeSignInCompleter<TUser>;
    }

    public static bool PasskeyWins<TUser>(IServiceProvider services)
        where TUser : class
    {
        if (services.GetService<ExplicitPasskeySignInCompleterMarker<TUser>>() is not null)
        {
            return true;
        }

        using var scope = services.CreateScope();
        var completer = scope.ServiceProvider.GetService<IPasskeySignInCompleter<TUser>>();
        return completer is not null && completer is not IdentityPasskeySignInCompleter<TUser>;
    }

    public static bool EmailCodeWins<TUser>(IServiceProvider services, IEmailCodeSignInCompleter<TUser> completer)
        where TUser : class
    {
        return services.GetService<ExplicitEmailCodeSignInCompleterMarker<TUser>>() is not null
            || completer is not IdentityEmailCodeSignInCompleter<TUser>;
    }

    public static bool PasskeyWins<TUser>(IServiceProvider services, IPasskeySignInCompleter<TUser> completer)
        where TUser : class
    {
        return services.GetService<ExplicitPasskeySignInCompleterMarker<TUser>>() is not null
            || completer is not IdentityPasskeySignInCompleter<TUser>;
    }

    public static bool ExternalWins<TUser>(IServiceProvider services)
        where TUser : class
    {
        if (services.GetServices<ExplicitExternalLoginCompleterMarker>().Any(marker => marker.UserType == typeof(TUser)))
        {
            return true;
        }

        using var scope = services.CreateScope();
        var completer = scope.ServiceProvider.GetService<IExternalLoginCompleter<TUser>>();
        return completer is not null && completer is not CookieExternalLoginCompleter<TUser>;
    }

    public static bool ExternalWins<TUser>(IServiceProvider services, IExternalLoginCompleter<TUser> completer)
        where TUser : class
    {
        return services.GetServices<ExplicitExternalLoginCompleterMarker>().Any(marker => marker.UserType == typeof(TUser))
            || completer is not CookieExternalLoginCompleter<TUser>;
    }
}
