namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="IAccessClaimsProvider{TUser}"/> to define your refresh token claims provider
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface IAccessClaimsProvider<TUser> : IClaimsProvider<TUser>
    where TUser : class
{
}