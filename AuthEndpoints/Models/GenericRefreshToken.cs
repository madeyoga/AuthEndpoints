using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Models;

public class GenericRefreshToken<TUser, TUserKey>
    where TUser : IdentityUser<TUserKey>
    where TUserKey : IEquatable<TUserKey>
{
    public Guid Id { get; set; }

    public TUserKey? UserId { get; set; }

    public TUser? User { get; set; }

    public string? Token { get; set; }

    public GenericRefreshToken()
    {

    }
}
