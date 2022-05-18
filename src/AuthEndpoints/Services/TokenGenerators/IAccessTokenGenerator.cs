namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="IAccessTokenGenerator{TUser}"/> to define your access token generator
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface IAccessTokenGenerator<TUser> : ITokenGenerator<TUser>
{
}
