namespace AuthEndpoints.Identity;

/// <summary>
/// Marks <c>POST /manage/password</c> so an unmapped password sign-in returns 404
/// before the sign-in and ReAuth checks.
/// </summary>
internal sealed class SetPasswordEndpointMetadata
{
    public static readonly SetPasswordEndpointMetadata Instance = new();

    private SetPasswordEndpointMetadata()
    {
    }
}
