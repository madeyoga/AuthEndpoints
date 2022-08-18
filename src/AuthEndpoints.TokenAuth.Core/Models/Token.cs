namespace AuthEndpoints.TokenAuth.Core;

public class Token<TKey, TUser>
{
    public int Id { get; set; }
    public string? Key { get; set; }
    public TKey? GetUserId { get; set; }
    public TUser? GetUser { get; set; }
}
