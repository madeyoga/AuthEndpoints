namespace AuthEndpoints.Services;
public interface IRefreshTokenClaimsProvider<TUser> : IClaimsProvider<TUser> 
    where TUser : class
{
}
