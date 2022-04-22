namespace AuthEndpoints.Services.Authenticators;

using AuthEndpoints.Models;
using AuthEndpoints.Models.Responses;
using AuthEndpoints.Services.Repositories;
using AuthEndpoints.Services.TokenGenerators;
using Microsoft.AspNetCore.Identity;

public class UserAuthenticator<TUserKey, TUser, TRefreshToken>
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
    where TRefreshToken : GenericRefreshToken<TUser, TUserKey>, new()
{
    private readonly IRefreshTokenRepository<TUserKey, TRefreshToken> refreshTokenRepository;
    private readonly ITokenGenerator<TUser> accessTokenGenerator;
    private readonly ITokenGenerator<TUser> refreshTokenGenerator;

    public UserAuthenticator(IRefreshTokenRepository<TUserKey, TRefreshToken> refreshTokenRepository,
        AccessTokenGenerator<TUserKey, TUser> accessTokenGenerator,
        RefreshTokenGenerator<TUserKey, TUser> refreshTokenGenerator)
    {
        this.refreshTokenRepository = refreshTokenRepository;
        this.accessTokenGenerator = accessTokenGenerator;
        this.refreshTokenGenerator = refreshTokenGenerator;
    }

    public async Task<AuthenticatedUserResponse> Authenticate(TUser user)
    {
        string accessToken = accessTokenGenerator.GenerateToken(user);
        string refreshToken = refreshTokenGenerator.GenerateToken(user);

        TRefreshToken refreshTokenDTO = new TRefreshToken(); // default(TRefreshToken)!;
        refreshTokenDTO.UserId = user.Id;
        refreshTokenDTO.Token = refreshToken;

        await refreshTokenRepository.Create(refreshTokenDTO);

        return new AuthenticatedUserResponse()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
        };
    }
}
