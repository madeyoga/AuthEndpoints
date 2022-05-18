namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="IRefreshTokenClaimsProvider{TUser}"/> to define your refresh token claims provider
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface IRefreshTokenClaimsProvider<TUser> : IClaimsProvider<TUser> 
    where TUser : class
{
}
