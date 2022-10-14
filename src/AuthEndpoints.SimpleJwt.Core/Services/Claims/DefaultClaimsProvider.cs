using System.Security.Claims;

namespace AuthEndpoints.SimpleJwt.Core.Services;

/// <summary>
/// Use <see cref="DefaultClaimsProvider"/> to get access token claims and refresh token claims
/// </summary>
/// <typeparam name="TUserKey"></typeparam>
/// <typeparam name="TUser"></typeparam>
public class DefaultClaimsProvider : IClaimsProvider
{
    /// <summary>
    /// Provide claims for access token
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    public virtual IEnumerable<Claim> ProvideAccessClaims(ClaimsPrincipal user)
    {
        return GetUserClaims(user);
    }

    /// <summary>
    /// Provide claims for refresh token
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    public virtual IEnumerable<Claim> ProvideRefreshClaims(ClaimsPrincipal user)
    {
        return GetUserClaims(user);
    }

    private static IEnumerable<Claim> GetUserClaims(ClaimsPrincipal user)
    {
        Claim? idClaim = user.FindFirst(ClaimTypes.NameIdentifier);
        if (idClaim == null)
        {
            throw new InvalidOperationException("Null identifier claim");
        }
        return new List<Claim>()
        {
            new Claim("id", idClaim.Value),
            new Claim(ClaimTypes.NameIdentifier, idClaim.Value),
            new Claim(ClaimTypes.Name, user.Identity!.Name!),
        };
    }
}
