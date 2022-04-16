using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Demo.Models;

public class User : IdentityUser
{
    public string? Nickname { get; set; }
    //public Tourney? Tournaments { get; set; }
    //public List<TeamMembership>? TeamMemberships { get; set; }
}
