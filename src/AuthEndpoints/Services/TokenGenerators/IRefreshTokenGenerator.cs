namespace AuthEndpoints.Services.TokenGenerators;
public interface IRefreshTokenGenerator<TUser> : ITokenGenerator<TUser> where TUser : class
{
}
