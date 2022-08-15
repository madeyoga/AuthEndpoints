using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.TokenAuth.Tests.Web.Models;

public class Token<TKey, TUser>
{
    public int Id { get; set; }
    public string? Key { get; set; }
    public TKey? GetUserId { get; set; }
    public TUser? GetUser { get; set; }
}
