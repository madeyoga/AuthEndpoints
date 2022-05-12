using AuthEndpoints.Models.Responses;

namespace AuthEndpoints.Services.Authenticators;

internal class TokenUserAuthenticator<TUser> : IAuthenticator<TUser, AuthenticatedTokenResponse>
    where TUser : class
{
    public async Task<AuthenticatedTokenResponse> Authenticate(TUser user)
    {
        return new AuthenticatedTokenResponse()
        {
            AccessToken = ""
        };
    }
}
