using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Models;

public class DefaultRefreshToken : GenericRefreshToken<IdentityUser, string>
{
}
