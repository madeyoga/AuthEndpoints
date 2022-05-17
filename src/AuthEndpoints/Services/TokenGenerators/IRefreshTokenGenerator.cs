namespace AuthEndpoints.Services;
public interface IRefreshTokenGenerator<TUser> : ITokenGenerator<TUser> where TUser : class
{
}
