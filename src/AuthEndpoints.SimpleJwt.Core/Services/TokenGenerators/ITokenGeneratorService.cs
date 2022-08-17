namespace AuthEndpoints.SimpleJwt.Core.Services;

public interface ITokenGeneratorService<TUser> : IAccessTokenGenerator<TUser>, IRefreshTokenGenerator<TUser>
{
}
