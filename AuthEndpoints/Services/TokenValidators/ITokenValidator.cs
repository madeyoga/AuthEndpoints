namespace AuthEndpoints.Services.TokenValidators;

public interface ITokenValidator
{
    bool Validate(string token);
}
