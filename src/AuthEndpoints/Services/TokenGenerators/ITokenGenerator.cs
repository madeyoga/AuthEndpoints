namespace AuthEndpoints.Services;

public interface ITokenGenerator<TUser>
{
    string Generate(TUser user);
}
