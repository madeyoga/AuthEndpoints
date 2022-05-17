namespace AuthEndpoints.Services;

public interface IAccessTokenClaimsProvider<TUser> : IClaimsProvider<TUser> 
    where TUser : class
{
}
