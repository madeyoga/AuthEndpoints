using System.Text.Json.Serialization;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.OpenIddict;

/// <summary>Returned once by create (confidential apps) and by secret rotation. Only the hash is stored.</summary>
public sealed record OAuthDeveloperAppSecret(
    [property: JsonPropertyName("app")] OAuthDeveloperAppInfo App,
    [property: JsonPropertyName("clientSecret")] string? ClientSecret);

internal sealed class DeveloperAppBody
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("homepageUrl")]
    public string? HomepageUrl { get; init; }

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("redirectUris")]
    public string[]? RedirectUris { get; init; }

    /// <summary>OpenID Connect only. Omit on update to keep the current list.</summary>
    [JsonPropertyName("postLogoutRedirectUris")]
    public string[]? PostLogoutRedirectUris { get; init; }

    /// <summary>Create only. Ignored on update, because it cannot change.</summary>
    [JsonPropertyName("confidential")]
    public bool Confidential { get; init; }

    public OAuthDeveloperAppInput ToInput() => new(Name, HomepageUrl, Description, RedirectUris)
    {
        PostLogoutRedirectUris = PostLogoutRedirectUris,
    };
}

internal static class OAuthDeveloperAppEndpoints
{
    public static RouteGroupBuilder Map(IEndpointRouteBuilder endpoints, string prefix)
    {
        var settings = endpoints.ServiceProvider.GetRequiredService<IOptions<OAuthServerOptions>>().Value;
        var group = endpoints.MapGroup(prefix)
            .WithTags("OAuth developer apps")
            .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = settings.AuthenticationScheme });

        group.MapGet("/", ListAsync)
            .WithName("ListOAuthDeveloperApps")
            .WithSummary("The signed-in user's OAuth apps")
            .Produces<OAuthDeveloperAppInfo[]>();
        group.MapPost("/", CreateAsync)
            .WithName("CreateOAuthDeveloperApp")
            .WithSummary("Register an OAuth app. A confidential app's client secret is returned once.")
            .Produces<OAuthDeveloperAppSecret>(StatusCodes.Status201Created)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status409Conflict)
            .RequireAntiforgery(allowBearer: false);
        group.MapGet("/{id:guid}", GetAsync)
            .WithName("GetOAuthDeveloperApp")
            .WithSummary("One of the signed-in user's OAuth apps")
            .Produces<OAuthDeveloperAppInfo>()
            .ProducesProblem(StatusCodes.Status404NotFound);
        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateOAuthDeveloperApp")
            .WithSummary("Edit an OAuth app's name, homepage, description, and redirect URIs")
            .Produces<OAuthDeveloperAppInfo>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAntiforgery(allowBearer: false);
        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteOAuthDeveloperApp")
            .WithSummary("Delete an OAuth app and revoke every token issued to it")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAntiforgery(allowBearer: false);
        group.MapPost("/{id:guid}/secret", RotateSecretAsync)
            .WithName("RotateOAuthDeveloperAppSecret")
            .WithSummary("Replace a confidential app's client secret. The new secret is returned once.")
            .Produces<OAuthDeveloperAppSecret>()
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAntiforgery(allowBearer: false);
        return group;
    }

    private static async Task<IResult> ListAsync(
        HttpContext http, IOAuthDeveloperAppService apps, IOptions<OAuthServerOptions> options, CancellationToken ct)
        => UserId(http, options.Value) is { } userId
            ? Results.Ok(await apps.ListAsync(userId, ct))
            : Results.Ok(Array.Empty<OAuthDeveloperAppInfo>());

    private static async Task<IResult> GetAsync(
        Guid id, HttpContext http, IOAuthDeveloperAppService apps, IOptions<OAuthServerOptions> options, CancellationToken ct)
    {
        var app = UserId(http, options.Value) is { } userId ? await apps.FindAsync(id, userId, ct) : null;
        return app is null ? NotFound() : Results.Ok(app);
    }

    private static async Task<IResult> CreateAsync(
        DeveloperAppBody body, HttpContext http, IOAuthDeveloperAppService apps, IOptions<OAuthServerOptions> options, CancellationToken ct)
    {
        if (UserId(http, options.Value) is not { } userId)
        {
            return NotFound();
        }

        var result = await apps.CreateAsync(userId, body.ToInput(), body.Confidential, ct);
        if (result.Outcome != OAuthDeveloperAppOutcome.Succeeded)
        {
            return Failure(result);
        }

        NoStore(http);
        return Results.Created(
            $"{http.Request.PathBase}{http.Request.Path.Value?.TrimEnd('/')}/{result.App!.Id}",
            new OAuthDeveloperAppSecret(result.App, result.ClientSecret));
    }

    private static async Task<IResult> UpdateAsync(
        Guid id, DeveloperAppBody body, HttpContext http, IOAuthDeveloperAppService apps, IOptions<OAuthServerOptions> options, CancellationToken ct)
    {
        if (UserId(http, options.Value) is not { } userId)
        {
            return NotFound();
        }

        var result = await apps.UpdateAsync(id, userId, body.ToInput(), ct);
        return result.Outcome == OAuthDeveloperAppOutcome.Succeeded ? Results.Ok(result.App) : Failure(result);
    }

    private static async Task<IResult> DeleteAsync(
        Guid id, HttpContext http, IOAuthDeveloperAppService apps, IOptions<OAuthServerOptions> options, CancellationToken ct)
        => UserId(http, options.Value) is { } userId && await apps.DeleteAsync(id, userId, ct)
            ? Results.NoContent()
            : NotFound();

    private static async Task<IResult> RotateSecretAsync(
        Guid id, HttpContext http, IOAuthDeveloperAppService apps, IOptions<OAuthServerOptions> options, CancellationToken ct)
    {
        if (UserId(http, options.Value) is not { } userId)
        {
            return NotFound();
        }

        var result = await apps.RotateSecretAsync(id, userId, ct);
        if (result.Outcome != OAuthDeveloperAppOutcome.Succeeded)
        {
            return Failure(result);
        }

        NoStore(http);
        return Results.Ok(new OAuthDeveloperAppSecret(result.App!, result.ClientSecret));
    }

    private static IResult Failure(OAuthDeveloperAppResult result) => result.Outcome switch
    {
        OAuthDeveloperAppOutcome.Invalid => Results.ValidationProblem(
            result.Errors!.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal)),
        OAuthDeveloperAppOutcome.LimitReached => Results.Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "App limit reached",
            detail: "Delete an app before registering another."),
        OAuthDeveloperAppOutcome.NotConfidential => Results.Problem(
            statusCode: StatusCodes.Status400BadRequest,
            title: "Public app",
            detail: "This app is public and has no client secret."),
        _ => NotFound(),
    };

    private static void NoStore(HttpContext http)
    {
        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers.Pragma = "no-cache";
    }

    private static string? UserId(HttpContext http, OAuthServerOptions options)
        => http.User.FindFirst(options.UserIdClaimType)?.Value;

    private static IResult NotFound()
        => Results.Problem(
            statusCode: StatusCodes.Status404NotFound,
            title: "App not found",
            detail: "No app with this id belongs to you.");
}
