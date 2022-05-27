namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="IRefreshClaimsProvider{TUser}"/> to define your refresh Token claims provider
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface IRefreshClaimsProvider<TUser> : IClaimsProvider<TUser>
    where TUser : class
{
}