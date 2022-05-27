using AuthEndpoints.Controllers;
using AuthEndpoints.Demo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Demo.Controllers;

public class UserController : BaseEndpointsController<string, MyCustomIdentityUser>
{
    public UserController(UserManager<MyCustomIdentityUser> userManager, IdentityErrorDescriber errorDescriber, IOptions<AuthEndpointsOptions> options) : base(userManager, errorDescriber, options)
    {
    }
}
