using AuthEndpoints.Controllers;
using AuthEndpoints.Demo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Demo.Controllers;

[Tags("Authentication")]
public class AuthenticationController : BaseEndpointsController<string, MyCustomIdentityUser>
{
    public AuthenticationController(UserManager<MyCustomIdentityUser> userManager, IdentityErrorDescriber errorDescriber, IOptions<AuthEndpointsOptions> options) : base(userManager, errorDescriber, options)
    {
    }
}
