namespace AuthEndpoints.Services;

public interface IJwtFactory<TUser>
{
    string Create(TUser user, string secret, string issuer, string audience, int expirationMinutes);
}
