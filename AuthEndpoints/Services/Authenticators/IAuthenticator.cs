namespace AuthEndpoints.Services.Authenticators;
internal interface IAuthenticator<TUser, TResponse> 
    where TUser : class
    where TResponse : class
{
    Task<TResponse> Authenticate(TUser user);
}
