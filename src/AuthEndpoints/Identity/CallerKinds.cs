using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;

namespace AuthEndpoints.Identity;

/// <summary>
/// Who is calling: a person directly, a client acting for a person, or an API key. Strings, so a host can add its own
/// kinds through its principal hooks. Read the kind with <see cref="CallerKindClaimsPrincipalExtensions.GetCallerKind"/>.
/// </summary>
public static class CallerKinds
{
    /// <summary>
    /// The claim that holds the caller kind on an identity: <c>ae:caller</c>. A host scheme sets it on the identities it
    /// creates. The built-in sign-in schemes are recognized without it (see <see cref="Person"/>).
    /// </summary>
    public const string ClaimType = "ae:caller";

    /// <summary>
    /// The RFC 8693 actor claim, <c>act</c>: a JSON object such as <c>{"client_id":"…"}</c> naming the client that acts for
    /// the subject. Read it with <see cref="CallerKindClaimsPrincipalExtensions.GetActingClientId"/>.
    /// </summary>
    public const string ActorClaimType = "act";

    /// <summary>
    /// A person calling directly: the Identity application cookie, an Identity bearer token, or an AuthEndpoints JWT.
    /// Those identities are recognized by their authentication type, so cookies and tokens issued before this claim
    /// existed are people too. The claim is not written into them.
    /// </summary>
    public const string Person = "person";

    /// <summary>An OAuth access token issued to a client acting for a person, or for a subject the person chose.</summary>
    public const string Delegated = "delegated";

    /// <summary>An API key.</summary>
    public const string ApiKey = "api_key";
}

/// <summary>Reads the caller kind and the acting client from a principal.</summary>
public static class CallerKindClaimsPrincipalExtensions
{
    /// <summary>
    /// The caller kind of the principal's authenticated identities (<see cref="CallerKinds"/>), or <see langword="null"/>
    /// when there is none or one of them has no known kind. When a policy authenticates with more than one scheme and both
    /// succeed, the principal holds an identity from each: then any kind other than <see cref="CallerKinds.Person"/> wins,
    /// so a person's cookie never makes a delegated token look like a person.
    /// </summary>
    public static string? GetCallerKind(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        string? kind = null;
        foreach (var identity in principal.Identities)
        {
            if (!identity.IsAuthenticated)
            {
                continue;
            }

            var current = GetCallerKind(identity);
            if (current is null)
            {
                return null;
            }

            if (kind is null || kind == CallerKinds.Person)
            {
                kind = current;
            }
        }

        return kind;
    }

    /// <summary>
    /// <see langword="true"/> when the principal has at least one authenticated identity and every one of them is a
    /// person calling directly. An identity with an unknown kind (a host scheme that sets no <see cref="CallerKinds.ClaimType"/>)
    /// is not a person.
    /// </summary>
    public static bool IsDirectPerson(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var any = false;
        foreach (var identity in principal.Identities)
        {
            if (!identity.IsAuthenticated)
            {
                continue;
            }

            if (GetCallerKind(identity) != CallerKinds.Person)
            {
                return false;
            }

            any = true;
        }

        return any;
    }

    /// <summary>
    /// The <c>client_id</c> in the <c>act</c> claim of an authenticated identity: the client acting for the subject of a
    /// delegated token. <see langword="null"/> for a person or an API key.
    /// </summary>
    public static string? GetActingClientId(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        foreach (var identity in principal.Identities)
        {
            if (!identity.IsAuthenticated || identity.FindFirst(CallerKinds.ActorClaimType)?.Value is not { Length: > 0 } act)
            {
                continue;
            }

            try
            {
                using var json = JsonDocument.Parse(act);
                if (json.RootElement.ValueKind == JsonValueKind.Object
                    && json.RootElement.TryGetProperty("client_id", out var clientId)
                    && clientId.ValueKind == JsonValueKind.String)
                {
                    return clientId.GetString();
                }
            }
            catch (JsonException)
            {
            }
        }

        return null;
    }

    /// <summary>The kind of one identity: its <see cref="CallerKinds.ClaimType"/> claim, else person for the built-in sign-in schemes.</summary>
    internal static string? GetCallerKind(ClaimsIdentity identity)
    {
        if (identity.FindFirst(CallerKinds.ClaimType)?.Value is { Length: > 0 } kind)
        {
            return kind;
        }

        return SignInSchemes.IsPrimaryIdentity(identity) ? CallerKinds.Person : null;
    }
}

/// <summary>
/// Succeeds when <see cref="CallerKindClaimsPrincipalExtensions.IsDirectPerson"/> holds: every authenticated identity is
/// a person calling directly. A delegated OAuth token, an API key, or an identity of unknown kind fails it, which gives
/// <c>403</c> to an authenticated caller. Handles itself, so it needs no handler registration.
/// </summary>
public sealed class DirectPersonRequirement : AuthorizationHandler<DirectPersonRequirement>, IAuthorizationRequirement
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, DirectPersonRequirement requirement)
    {
        if (context.User.IsDirectPerson())
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

public static class DirectPersonAuthorizationExtensions
{
    /// <summary>
    /// Requires a signed-in person calling directly: refuses delegated OAuth tokens, API keys, and identities of unknown
    /// kind. Use it for actions only a person may take, such as changing a password or approving OAuth consent.
    /// </summary>
    public static AuthorizationPolicyBuilder RequireDirectPerson(this AuthorizationPolicyBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.RequireAuthenticatedUser().AddRequirements(new DirectPersonRequirement());
    }

    /// <summary>
    /// Adds <see cref="DirectPersonRequirement"/> to the endpoint's authorization. It names no authentication scheme, so
    /// pair it with the route's own (<c>RequireAuthorization</c>, <c>RequireAuthEndpointsUser</c>), or the default scheme
    /// is used. A caller that authenticates but is not a person directly gets <c>403</c>.
    /// </summary>
    public static TBuilder RequireDirectPerson<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.RequireAuthorization(DirectPersonPolicy.Instance);
    }
}

internal static class DirectPersonPolicy
{
    public static readonly AuthorizationPolicy Instance = new AuthorizationPolicyBuilder().RequireDirectPerson().Build();
}
