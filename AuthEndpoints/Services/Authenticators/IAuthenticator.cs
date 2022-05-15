namespace AuthEndpoints.Services.Authenticators;
internal interface IAuthenticator<TUser, TResponse> 
    where TUser : class
{
    Task<TResponse> Authenticate(TUser user);
}
