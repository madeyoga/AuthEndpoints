namespace AuthEndpoints.OpenIddict;

/// <summary>The developer app whose owner the consent card is about to show.</summary>
/// <param name="AppId">The <c>OAuthDeveloperApps</c> row id.</param>
/// <param name="ClientId">The app's client id.</param>
/// <param name="OwnerId">The owning user's id, as a string.</param>
public sealed record OAuthDeveloperAppOwnerContext(Guid AppId, string ClientId, string OwnerId);

/// <summary>
/// Describes who built a developer app, for the <c>owner</c> field of the consent card. The card is shown to other
/// users, so return only what the owner agreed to make public, for example a display name or organization they set
/// on a developer profile, not their email or Identity user name. Register it with
/// <c>AddAuthEndpointsOpenIddict(...).AddDeveloperAppOwnerDisplay&lt;T&gt;()</c>. By default nothing is shown.
/// </summary>
public interface IOAuthDeveloperAppOwnerDisplay
{
    /// <summary>The text to show, or <see langword="null"/> to show nothing. Called on every card fetch for a developer app.</summary>
    ValueTask<string?> GetOwnerAsync(OAuthDeveloperAppOwnerContext context, CancellationToken cancellationToken);
}

/// <summary>The default: no owner is shown.</summary>
internal sealed class NoOAuthDeveloperAppOwnerDisplay : IOAuthDeveloperAppOwnerDisplay
{
    public ValueTask<string?> GetOwnerAsync(OAuthDeveloperAppOwnerContext context, CancellationToken cancellationToken)
        => ValueTask.FromResult<string?>(null);
}
