using AuthEndpoints.Controllers;
using AuthEndpoints.Demo.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Demo.Controllers;

[Tags("Authentication")]
public class BasicAuthController // : BasicAuthenticationController<string, MyCustomIdentityUser>
{
    public BasicAuthController(UserManager<MyCustomIdentityUser> userManager,
        IdentityErrorDescriber errorDescriber, 
        IOptions<AuthEndpointsOptions> options, 
        IEmailSender emailSender, 
        IEmailFactory emailFactory) // : base(userManager, errorDescriber, options, emailSender, emailFactory)
    {
    }
}
