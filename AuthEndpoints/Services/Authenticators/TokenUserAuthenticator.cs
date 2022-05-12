using AuthEndpoints.Models.Responses;

namespace AuthEndpoints.Services.Authenticators;

public class TokenUserAuthenticator<TUser> : IAuthenticator<TUser, AuthenticatedTokenResponse>
    where TUser : class
{
    public Task<AuthenticatedTokenResponse> Authenticate(TUser user)
    {
        return Task.FromResult(new AuthenticatedTokenResponse()
        {
            AccessToken = ""
        });
    }
}
