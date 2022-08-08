namespace AuthEndpoints.Core.Services;

public interface ITokenGeneratorService<TUser> : IAccessTokenGenerator<TUser>, IRefreshTokenGenerator<TUser>
{
}
