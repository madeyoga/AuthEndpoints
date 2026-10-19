namespace AuthEndpoints.Jwt;

public interface IAuthenticator<TUser>
    where TUser : class
{
    Task<AuthenticationResult<TUser>> AuthenticateAsync(string username, string password);
}
