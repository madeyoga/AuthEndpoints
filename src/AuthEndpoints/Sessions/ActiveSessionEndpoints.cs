using AuthEndpoints.Identity;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Sessions;

/// <summary>
/// One row of <c>GET /sessions</c>.
/// </summary>
/// <param name="Id">Session id; pass it to <c>DELETE /sessions/{id}</c>.</param>
/// <param name="UserAgent">User-Agent of the sign-in request.</param>
/// <param name="CreatedAt">Sign-in time (UTC).</param>
/// <param name="LastSeenAt">Last use (UTC), updated at most once per <see cref="ActiveSessionOptions.LastSeenUpdateInterval"/>.</param>
/// <param name="Current"><see langword="true"/> for the session making this request.</param>
public sealed record ActiveSessionInfo(
    string Id,
    string? UserAgent,
    DateTime CreatedAt,
    DateTime LastSeenAt,
    bool Current);

/// <summary>
/// Result of <c>POST /sessions/revokeOthers</c>.
/// </summary>
/// <param name="Revoked">Number of sessions ended.</param>
public sealed record RevokeOtherSessionsResponse(int Revoked);

public static class ActiveSessionEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps <c>GET /sessions</c> (the caller's sessions, current one marked),
    /// <c>DELETE /sessions/{id}</c>, and <c>POST /sessions/revokeOthers</c>.
    /// Revoking needs a recent re-authentication (<c>RequireReauth</c>) and, for cookie callers, a CSRF token.
    /// Call <see cref="ActiveSessionServiceCollectionExtensions.AddActiveSessions{TUser, TContext}(Microsoft.Extensions.DependencyInjection.IServiceCollection, System.Action{ActiveSessionOptions}?)"/> first.
    /// </summary>
    public static IEndpointConventionBuilder MapActiveSessionEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        const string mapMethod = nameof(MapActiveSessionEndpoints);
        AuthEndpointsModules.ThrowIfMissing<ActiveSessionsModule>(endpoints, "AddActiveSessions", mapMethod);

        var group = endpoints.MapGroup("/sessions");

        group.MapGet("", ActiveSessionEndpoints<TUser>.List)
            .RequireAuthEndpointsUser()
            .WithSummary("List the current user's signed-in sessions.")
            .WithName("ActiveSessionsList")
            .Track(endpoints, mapMethod);

        group.MapDelete("/{id}", ActiveSessionEndpoints<TUser>.Revoke)
            .RequireAuthEndpointsUser()
            .RequireReauth()
            .RequireAntiforgery()
            .WithSummary("Sign out one of the current user's sessions.")
            .WithName("ActiveSessionsRevoke")
            .Track(endpoints, mapMethod);

        group.MapPost("/revokeOthers", ActiveSessionEndpoints<TUser>.RevokeOthers)
            .RequireAuthEndpointsUser()
            .RequireReauth()
            .RequireAntiforgery()
            .WithSummary("Sign out every session except the current one.")
            .WithName("ActiveSessionsRevokeOthers")
            .Track(endpoints, mapMethod);

        return group;
    }
}

internal static class ActiveSessionEndpoints<TUser>
    where TUser : class
{
    public static async Task<Results<Ok<List<ActiveSessionInfo>>, UnauthorizedHttpResult>> List(
        HttpContext context,
        UserManager<TUser> userManager,
        IActiveSessionStore store)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return TypedResults.Unauthorized();
        }

        var userId = await userManager.GetUserIdAsync(user);
        var stamp = userManager.SupportsUserSecurityStamp ? await userManager.GetSecurityStampAsync(user) : null;
        var current = ActiveSessionRequest.Current(context.User);
        var sessions = await store.ListAsync(userId, stamp);

        return TypedResults.Ok(sessions
            .Select(s => new ActiveSessionInfo(
                s.Id,
                s.UserAgent,
                ActiveSessionStore.AsUtc(s.CreatedAt),
                ActiveSessionStore.AsUtc(s.LastSeenAt),
                string.Equals(s.Id, current, StringComparison.Ordinal)))
            .ToList());
    }

    public static async Task<Results<NoContent, NotFound, UnauthorizedHttpResult>> Revoke(
        string id,
        HttpContext context,
        UserManager<TUser> userManager,
        IActiveSessionStore store)
    {
        var userId = userManager.GetUserId(context.User);
        if (string.IsNullOrEmpty(userId))
        {
            return TypedResults.Unauthorized();
        }

        return await store.RevokeAsync(userId, id)
            ? TypedResults.NoContent()
            : TypedResults.NotFound();
    }

    public static async Task<Results<Ok<RevokeOtherSessionsResponse>, UnauthorizedHttpResult>> RevokeOthers(
        HttpContext context,
        UserManager<TUser> userManager,
        IActiveSessionStore store)
    {
        var userId = userManager.GetUserId(context.User);
        if (string.IsNullOrEmpty(userId))
        {
            return TypedResults.Unauthorized();
        }

        var revoked = await store.RevokeOthersAsync(userId, ActiveSessionRequest.Current(context.User));
        return TypedResults.Ok(new RevokeOtherSessionsResponse(revoked));
    }
}
