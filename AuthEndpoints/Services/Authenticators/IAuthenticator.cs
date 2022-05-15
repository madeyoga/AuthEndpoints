namespace AuthEndpoints.Services.Authenticators;
public interface IAuthenticator<TUser, TResponse> 
    where TUser : class
{
    Task<TResponse> Authenticate(TUser user);
}
