namespace AuthEndpoints.Services.TokenGenerators;

public interface ITokenGenerator<TUser>
{
    string Generate(TUser user);
}
