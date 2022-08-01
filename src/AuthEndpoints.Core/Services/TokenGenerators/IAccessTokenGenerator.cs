namespace AuthEndpoints.Services;
public interface IAccessTokenGenerator<TUser>
{
    string GenerateAccessToken(TUser user);
}
