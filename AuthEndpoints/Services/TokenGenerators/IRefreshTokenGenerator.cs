namespace AuthEndpoints.Services.TokenGenerators;
internal interface IRefreshTokenGenerator<TUser> : ITokenGenerator<TUser> where TUser : class
{
}
