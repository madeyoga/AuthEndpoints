namespace AuthEndpoints.SimpleJwt.Core.Services;

public interface ITokenGeneratorService : IAccessTokenGenerator, IRefreshTokenGenerator
{
}
