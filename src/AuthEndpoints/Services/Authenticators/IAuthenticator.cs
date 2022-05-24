using AuthEndpoints.Models;

namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="IAuthenticator{TUser}"/> to define your authenticator
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface IAuthenticator<TUser>
    where TUser : class
{
    /// <summary>
    /// Implements this method to verify a set of credentials, username and password for the default case
    /// </summary>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <returns>An instance of TUser if credentials are valid, else return null</returns>
    Task<TUser?> Authenticate(string username, string password);

    /// <summary>
    /// Implements this method to log a user in
    /// </summary>
    /// <param name="user"></param>
    /// <returns>An instance of <see cref="AuthenticatedUserResponse"/></returns>
    Task<AuthenticatedUserResponse> Login(TUser user);
}