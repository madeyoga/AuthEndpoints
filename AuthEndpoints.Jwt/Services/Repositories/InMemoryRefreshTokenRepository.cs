using AuthEndpoints.Jwt.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Jwt.Services.Repositories;

public class InMemoryRefreshTokenRepository<TUserKey, TUser, TRefreshToken> : IRefreshTokenRepository<TUserKey, TRefreshToken>
    where TUserKey : IEquatable<TUserKey>
    where TUser : IdentityUser<TUserKey>
    where TRefreshToken : GenericRefreshToken<TUser, TUserKey>
{
    private readonly List<TRefreshToken> refreshTokens = new List<TRefreshToken>();

    public Task Create(TRefreshToken refreshToken)
    {
        refreshToken.Id = Guid.NewGuid();

        refreshTokens.Add(refreshToken);

        return Task.CompletedTask;
    }

    public Task Delete(Guid refreshTokenId)
    {
        refreshTokens.RemoveAll(rt => rt.Id == refreshTokenId);

        return Task.CompletedTask;
    }

    public Task DeleteAll(TUserKey userId)
    {
        refreshTokens.RemoveAll(rt => rt.UserId!.Equals(userId));

        return Task.CompletedTask;
    }

    public Task<TRefreshToken?> GetByToken(string token)
    {
        TRefreshToken? refreshToken = refreshTokens.FirstOrDefault(refreshToken => refreshToken.Token == token);
        return Task.FromResult(refreshToken);
    }
}

