using System.Security.Claims;
using AuthEndpoints.Jwt;
using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.Sessions;

/// <summary>
/// Adds the session id to JWT access tokens so the session list can mark the caller's session.
/// </summary>
internal sealed class ActiveSessionAccessTokenGenerator : IAccessTokenGenerator
{
    private readonly IAccessTokenGenerator _inner;
    private readonly IHttpContextAccessor _http;

    public ActiveSessionAccessTokenGenerator(IAccessTokenGenerator inner, IHttpContextAccessor http)
    {
        _inner = inner;
        _http = http;
    }

    public IAccessTokenGenerator Inner => _inner;

    public string GenerateAccessToken(ClaimsPrincipal user)
    {
        var sessionId = ActiveSessionRequest.GetOrAllocate(_http.HttpContext);
        var copy = new ClaimsPrincipal(user.Identities.Select(identity => identity.Clone()));
        ActiveSessionRequest.SetClaim(copy, sessionId);
        return _inner.GenerateAccessToken(copy);
    }
}

/// <summary>
/// Ties each refresh-token family to one session record. A new family is a new session;
/// rotation keeps the session, refresh fails once the session has ended, and revoking the
/// family ends the session.
/// </summary>
internal sealed class ActiveSessionRefreshTokenService : IRefreshTokenService
{
    private readonly IRefreshTokenService _inner;
    private readonly IActiveSessionStore _store;
    private readonly IHttpContextAccessor _http;

    public ActiveSessionRefreshTokenService(
        IRefreshTokenService inner,
        IActiveSessionStore store,
        IHttpContextAccessor http)
    {
        _inner = inner;
        _store = store;
        _http = http;
    }

    public IRefreshTokenService Inner => _inner;

    public Task<RefreshToken?> GetRefreshTokenAsync(string rawToken) => _inner.GetRefreshTokenAsync(rawToken);

    public Task RevokeAsync(RefreshToken refreshToken) => _inner.RevokeAsync(refreshToken);

    public bool IsValid(RefreshToken refreshToken) => _inner.IsValid(refreshToken);

    public async Task RevokeFamilyAsync(string familyId)
    {
        await _inner.RevokeFamilyAsync(familyId);
        await _store.EndFamilyAsync(familyId);
    }

    public async Task<RefreshToken> CreateAsync(string userId, string securityStamp, string? familyId = null)
    {
        var token = await _inner.CreateAsync(userId, securityStamp, familyId);
        var http = _http.HttpContext;

        var sessionId = familyId is null ? null : await _store.SessionIdForFamilyAsync(familyId);
        sessionId ??= ActiveSessionRequest.GetOrAllocate(http);

        await _store.CreateAsync(
            sessionId,
            userId,
            http?.Request.Headers.UserAgent.ToString(),
            securityStamp,
            token.AbsoluteExpiresAt);
        await _store.SetTokenSessionAsync(token.Id, sessionId);
        ActiveSessionRequest.Set(http, sessionId);
        return token;
    }

    public async Task<RefreshToken?> RotateAsync(RefreshToken refreshToken, string securityStamp)
    {
        var sessionId = await _store.SessionIdForTokenAsync(refreshToken.Id);
        if (sessionId is not null && !await _store.IsActiveAsync(sessionId))
        {
            await _inner.RevokeFamilyAsync(refreshToken.FamilyId);
            return null;
        }

        var successor = await _inner.RotateAsync(refreshToken, securityStamp);
        if (successor is null)
        {
            return null;
        }

        var http = _http.HttpContext;
        if (sessionId is null)
        {
            // Family issued before sessions were turned on: adopt it.
            sessionId = ActiveSessionRequest.NewId();
            await _store.CreateAsync(
                sessionId,
                successor.UserId,
                http?.Request.Headers.UserAgent.ToString(),
                securityStamp,
                successor.AbsoluteExpiresAt);
        }
        else
        {
            var session = await _store.FindAsync(sessionId);
            if (session is not null)
            {
                await _store.TouchAsync(session, expiresAt: null);
            }
        }

        await _store.SetTokenSessionAsync(successor.Id, sessionId);
        ActiveSessionRequest.Set(http, sessionId);
        return successor;
    }
}
