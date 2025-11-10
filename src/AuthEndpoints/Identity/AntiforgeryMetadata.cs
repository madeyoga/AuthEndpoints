using Microsoft.AspNetCore.Antiforgery;

namespace AuthEndpoints.Identity;

public sealed class AntiforgeryMetadata(bool required) : IAntiforgeryMetadata
{
    public static readonly IAntiforgeryMetadata ValidationRequired = new AntiforgeryMetadata(true);
    public static readonly IAntiforgeryMetadata ValidationNotRequired = new AntiforgeryMetadata(false);

    public bool RequiresValidation { get; } = required;
}
