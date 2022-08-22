namespace AuthEndpoints.Core.Services;

public interface ILoginService<TUser> where TUser : class
{
    Task<object> Login(TUser user);
}
