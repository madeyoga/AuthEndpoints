namespace AuthEndpoints.Services;

public interface ITokenGeneratorService<TUser> : IAccessTokenGenerator<TUser>, IRefreshTokenGenerator<TUser>
{

}
