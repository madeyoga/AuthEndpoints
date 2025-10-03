using Microsoft.AspNetCore.Identity;

namespace Demo.Models;

public class AppUser : IdentityUser
{
    public bool IsSuperUser { get; set; } = false;
    public string DisplayName { get; set; } = string.Empty;
}
