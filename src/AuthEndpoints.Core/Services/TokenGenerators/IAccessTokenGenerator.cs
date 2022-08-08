namespace AuthEndpoints.Core.Services;
public interface IAccessTokenGenerator<TUser>
{
    string GenerateAccessToken(TUser user);
}
