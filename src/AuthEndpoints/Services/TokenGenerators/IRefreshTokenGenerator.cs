namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="IRefreshTokenGenerator{TUser}"/> to define your refresh token generator
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface IRefreshTokenGenerator<TUser> : ITokenGenerator<TUser> where TUser : class
{
}
