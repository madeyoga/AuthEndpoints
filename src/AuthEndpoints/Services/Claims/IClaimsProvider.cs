using System.Security.Claims;

namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="IClaimsProvider{TUser}"/> to define your claims provider
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface IClaimsProvider<TUser> where TUser : class
{
    /// <summary>
    /// Use this method to get a list of claims for the given user
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    IList<Claim> provideAccessClaims(TUser user);

    /// <summary>
    /// Use this method to get a list of claims for the given user
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    IList<Claim> provideRefreshClaims(TUser user);
}
