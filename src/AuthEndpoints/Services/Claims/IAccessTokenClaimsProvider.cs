namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="IAccessTokenClaimsProvider{TUser}"/> to define your refresh token claims provider
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface IAccessTokenClaimsProvider<TUser> : IClaimsProvider<TUser> 
    where TUser : class
{
}
