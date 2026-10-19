namespace AuthEndpoints.Identity;

public static class AuthEndpointsEndpointNames
{
    /// <summary>
    /// Name of the confirm-email endpoint for <typeparamref name="TUser"/>.
    /// The value is <c>MapIdentityManagementApi-{TUser}-confirmEmail</c>, using <see cref="System.Reflection.MemberInfo.Name"/>.
    /// </summary>
    public static string ConfirmEmail<TUser>()
        where TUser : class
        => $"MapIdentityManagementApi-{typeof(TUser).Name}-confirmEmail";
}
