namespace AuthEndpoints.Jwt.Services.TokenValidators;

public interface ITokenValidator
{
    bool Validate(string token);
}
