namespace AuthEndpoints.Services;

/// <summary>
/// Implements IAuthenticator to define your authenticator
/// </summary>
/// <typeparam name="TUser"></typeparam>
/// <typeparam name="TResponse"></typeparam>
public interface IAuthenticator<TUser, TResponse> 
    where TUser : class
{
    /// <summary>
    /// Authenticate user
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    Task<TResponse> Authenticate(TUser user);
}
