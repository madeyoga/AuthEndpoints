namespace AuthEndpoints.Identity;

/// <summary>
/// Stable endpoint names used by link generation.
/// </summary>
public static class AuthEndpointsEndpointNames
{
    /// <summary>
    /// Name of the confirm-email endpoint for <typeparamref name="TUser"/>.
    /// The value is <c>MapIdentityManagementApi-{TUser}-confirmEmail</c>, using <see cref="Type.Name"/>.
    /// </summary>
    public static string ConfirmEmail<TUser>()
        where TUser : class
        => $"MapIdentityManagementApi-{typeof(TUser).Name}-confirmEmail";
}
