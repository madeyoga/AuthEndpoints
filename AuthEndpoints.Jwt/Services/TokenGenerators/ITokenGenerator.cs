namespace AuthEndpoints.Jwt.Services.TokenGenerators;

public interface ITokenGenerator<TUser>
{
    string GenerateToken(TUser user);
}
