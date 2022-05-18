using Microsoft.AspNetCore.Identity;
using System.Text.Json.Serialization;

namespace AuthEndpoints.Demo.Models;

public class MyCustomIdentityUser : IdentityUser
{
    public string? Nickname { get; set; }

    [JsonIgnore]
    public override string PasswordHash { get => base.PasswordHash; set => base.PasswordHash = value; }
    [JsonIgnore]
    public override string SecurityStamp { get => base.SecurityStamp; set => base.SecurityStamp = value; }
    [JsonIgnore]
    public override string ConcurrencyStamp { get => base.ConcurrencyStamp; set => base.ConcurrencyStamp = value; }
}
