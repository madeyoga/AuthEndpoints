namespace AuthEndpoints.SimpleJwt.Core.Services;
public interface IAccessTokenGenerator<TUser>
{
    string GenerateAccessToken(TUser user);
}
