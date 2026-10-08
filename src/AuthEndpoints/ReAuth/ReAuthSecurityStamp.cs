using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.ReAuth;

internal interface IReAuthSecurityStamp
{
    bool SupportsUserSecurityStamp { get; }

    Task<string?> GetCurrentStampAsync(ClaimsPrincipal signedInUser);
}

internal sealed class ReAuthSecurityStamp<TUser> : IReAuthSecurityStamp
    where TUser : class
{
    private readonly UserManager<TUser> _users;

    public ReAuthSecurityStamp(UserManager<TUser> users)
    {
        _users = users;
    }

    public bool SupportsUserSecurityStamp => _users.SupportsUserSecurityStamp;

    public async Task<string?> GetCurrentStampAsync(ClaimsPrincipal signedInUser)
    {
        var user = await _users.GetUserAsync(signedInUser);
        if (user is null || !_users.SupportsUserSecurityStamp)
        {
            return null;
        }

        return await _users.GetSecurityStampAsync(user);
    }
}

internal static class ReAuthSecurityStampFactory
{
    public static IReAuthSecurityStamp Create(IServiceProvider services, IServiceCollection registrations)
    {
        var userTypes = registrations
            .Select(descriptor => descriptor.ServiceType)
            .Where(type => type.IsGenericType && type.GetGenericTypeDefinition() == typeof(UserManager<>))
            .Select(type => type.GenericTypeArguments[0])
            .Distinct()
            .ToArray();

        if (userTypes.Length != 1)
        {
            throw new InvalidOperationException(
                "ReAuth requires exactly one UserManager<TUser> registration to check the security stamp.");
        }

        var stampType = typeof(ReAuthSecurityStamp<>).MakeGenericType(userTypes[0]);
        return (IReAuthSecurityStamp)ActivatorUtilities.CreateInstance(services, stampType);
    }
}
