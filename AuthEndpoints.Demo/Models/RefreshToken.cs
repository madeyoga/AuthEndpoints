using AuthEndpoints.Jwt.Models;

namespace AuthEndpoints.Demo.Models;

public class RefreshToken : GenericRefreshToken<MyCustomIdentityUser, string>
{
}
