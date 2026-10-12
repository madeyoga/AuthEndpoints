namespace AuthEndpoints.Identity;

/// <summary>
/// Password login handler mapped by <see cref="IdentityApiEndpointRouteBuilderExtensions.MapPasswordEndpoints{TUser}"/>.
/// </summary>
public enum PasswordLoginMode
{
    /// <summary>
    /// Maps <c>POST /login</c> to the application-cookie handler.
    /// </summary>
    Cookie = 0,

    /// <summary>
    /// Maps <c>POST /login</c> to the Identity bearer handler.
    /// </summary>
    IdentityBearer = 1,

    /// <summary>
    /// Does not map <c>POST /login</c>.
    /// </summary>
    None = 2,
}
