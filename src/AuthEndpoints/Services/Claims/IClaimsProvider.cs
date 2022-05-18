using System.Security.Claims;

namespace AuthEndpoints.Services;

public interface IClaimsProvider<TUser> where TUser : class
{
    /// <summary>
    /// Use this method to get a list of claims for the given user
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    IList<Claim> provideClaims(TUser user);
}
