namespace AuthEndpoints.Services;

/// <summary>
/// Implements <see cref="ITokenGenerator{TUser}"/> to define your token generator
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface ITokenGenerator<TUser>
{
    string Generate(TUser user);
}
