using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Demo.Models;

public class MyCustomIdentityUser : IdentityUser
{
    public string? Nickname { get; set; }
}
