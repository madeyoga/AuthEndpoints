namespace AuthEndpoints.OpenIddict;

/// <summary>Fixed routes and names used by the authorization server.</summary>
public static class OAuthServerConstants
{
    public const string AuthorizationEndpointPath = "/connect/authorize";
    public const string TokenEndpointPath = "/connect/token";
    public const string RevocationEndpointPath = "/connect/revoke";
    public const string RegistrationEndpointPath = "/connect/register";
    public const string AuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server";
    public const string ProtectedResourceMetadataPath = "/.well-known/oauth-protected-resource";

    public const string OfflineAccessScope = "offline_access";

    /// <summary>Application setting that marks a dynamically registered client and holds its creation time.</summary>
    public const string CreatedAtSetting = "created_at";

    /// <summary>Application setting that marks a developer app and holds its <c>OAuthDeveloperApps</c> row id.</summary>
    public const string DeveloperAppSetting = "ae_developer_app";

    /// <summary>
    /// Reference tokens are 256 random bytes encoded as base64url (342 characters).
    /// The OpenIddict EF model caps that column at 100, which PostgreSQL and SQL Server would reject.
    /// </summary>
    public const int ReferenceTokenLength = 512;

    /// <summary>Table that holds pending consent requests.</summary>
    public const string RequestTable = "OAuthRequests";

    /// <summary>Table that holds developer apps.</summary>
    public const string DeveloperAppTable = "OAuthDeveloperApps";

    /// <summary>Grant claim with the approving user's id. Kept in codes and refresh tokens, never in access tokens.</summary>
    public const string UserIdClaim = "ae_user_id";

    /// <summary>Grant claim with the approving user's security stamp at approval.</summary>
    public const string UserStampClaim = "ae_user_stamp";

    /// <summary>Fallback display name for a client without one.</summary>
    public const string FallbackClientName = "OAuth client";
}
