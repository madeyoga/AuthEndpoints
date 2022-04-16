using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Jwt.Models;

public class DefaultRefreshToken : GenericRefreshToken<IdentityUser, string>
{
}
