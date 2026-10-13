using System.Runtime.CompilerServices;

namespace AuthEndpoints.Identity;

/// <summary>
/// Set when a password sign-in route (<c>POST /login</c> or JWT <c>POST /create</c>) is mapped.
/// Sign-up and recovery do not set it.
/// </summary>
internal static class PasswordSignInMap
{
    private static readonly ConditionalWeakTable<IServiceProvider, Marker> Markers = new();

    public static void Mark(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Markers.GetOrCreateValue(services).Mapped = true;
    }

    public static bool IsMapped(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        return Markers.TryGetValue(services, out var marker) && marker.Mapped;
    }

    private sealed class Marker
    {
        public bool Mapped { get; set; }
    }
}
