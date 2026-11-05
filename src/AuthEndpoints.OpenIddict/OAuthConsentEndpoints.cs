using System.Text.Json.Serialization;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.OpenIddict;

/// <summary>Consent card returned by <c>GET {prefix}/requests/{id}</c>.</summary>
public sealed record OAuthConsentCard(
    [property: JsonPropertyName("id")] Guid Id,
    [property: JsonPropertyName("clientId")] string ClientId,
    [property: JsonPropertyName("clientName")] string ClientName,
    [property: JsonPropertyName("redirectHost")] string RedirectHost,
    [property: JsonPropertyName("scopes")] IReadOnlyList<string> Scopes,
    [property: JsonPropertyName("resource")] string Resource,
    [property: JsonPropertyName("expiresAt")] DateTimeOffset ExpiresAt)
{
    /// <summary>The developer app's homepage. <see langword="null"/> for seeded and dynamically registered clients.</summary>
    [JsonPropertyName("homepageUrl")]
    public string? HomepageUrl { get; init; }

    /// <summary>The developer app's description, when it has one. <see langword="null"/> for other clients.</summary>
    [JsonPropertyName("description")]
    public string? Description { get; init; }

    /// <summary>Whether the developer app has a client secret. <see langword="null"/> for other clients.</summary>
    [JsonPropertyName("confidential")]
    public bool? Confidential { get; init; }

    /// <summary>Who built the developer app, from the host's <see cref="IOAuthDeveloperAppOwnerDisplay"/>. <see langword="null"/> by default.</summary>
    [JsonPropertyName("owner")]
    public string? Owner { get; init; }
}

/// <summary>Where the consent page sends the browser next.</summary>
public sealed record OAuthConsentRedirect([property: JsonPropertyName("redirectUrl")] string RedirectUrl);

internal static class OAuthConsentEndpoints
{
    public static RouteGroupBuilder Map(IEndpointRouteBuilder endpoints, string prefix)
    {
        var settings = endpoints.ServiceProvider.GetRequiredService<IOptions<OAuthServerOptions>>().Value;
        var group = endpoints.MapGroup(prefix)
            .WithTags("OAuth")
            .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = settings.AuthenticationScheme });

        group.MapGet("/requests/{id:guid}", GetAsync)
            .WithName("GetOAuthConsentRequest")
            .WithSummary("The consent card for one pending OAuth request")
            .Produces<OAuthConsentCard>()
            .ProducesProblem(StatusCodes.Status404NotFound);
        group.MapPost("/requests/{id:guid}/approve", ApproveAsync)
            .WithName("ApproveOAuthConsentRequest")
            .WithSummary("Approve the OAuth request and get the client redirect")
            .Produces<OAuthConsentRedirect>()
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAntiforgery();
        group.MapPost("/requests/{id:guid}/deny", DenyAsync)
            .WithName("DenyOAuthConsentRequest")
            .WithSummary("Deny the OAuth request and get the client redirect")
            .Produces<OAuthConsentRedirect>()
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAntiforgery();
        return group;
    }

    private static async Task<IResult> GetAsync(
        Guid id, HttpContext http, IOAuthConsentService consent, IOptions<OAuthServerOptions> options, CancellationToken ct)
    {
        var userId = UserId(http, options.Value);
        var request = userId is null ? null : await consent.FindAsync(id, userId, ct);
        return request is null
            ? NotFound()
            : Results.Ok(new OAuthConsentCard(
                request.Id, request.ClientId, request.ClientName, request.RedirectHost, request.Scopes, request.Resource, request.ExpiresAt)
            {
                HomepageUrl = request.HomepageUrl,
                Description = request.Description,
                Confidential = request.Confidential,
                Owner = request.Owner,
            });
    }

    private static async Task<IResult> ApproveAsync(
        Guid id, HttpContext http, IOAuthConsentService consent, IOptions<OAuthServerOptions> options, CancellationToken ct)
    {
        var userId = UserId(http, options.Value);
        if (userId is null)
        {
            return NotFound();
        }

        var result = await consent.ApproveAsync(id, userId, ct);
        return result.Status switch
        {
            OAuthConsentStatus.Approved => Results.Ok(new OAuthConsentRedirect(result.RedirectUrl!)),
            OAuthConsentStatus.Declined => Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "Request declined",
                detail: "The server did not issue a code for this request."),
            _ => NotFound(),
        };
    }

    private static async Task<IResult> DenyAsync(
        Guid id, HttpContext http, IOAuthConsentService consent, IOptions<OAuthServerOptions> options, CancellationToken ct)
    {
        var userId = UserId(http, options.Value);
        if (userId is null)
        {
            return NotFound();
        }

        var result = await consent.DenyAsync(id, userId, ct);
        return result.Status == OAuthConsentStatus.Denied
            ? Results.Ok(new OAuthConsentRedirect(result.RedirectUrl!))
            : NotFound();
    }

    private static string? UserId(HttpContext http, OAuthServerOptions options)
        => http.User.FindFirst(options.UserIdClaimType)?.Value;

    private static IResult NotFound()
        => Results.Problem(
            statusCode: StatusCodes.Status404NotFound,
            title: "Request not found",
            detail: "This consent request is unknown, expired, or already used.");
}
