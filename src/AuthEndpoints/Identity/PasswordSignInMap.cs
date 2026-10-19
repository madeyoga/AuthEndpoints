using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.Identity;

/// <summary>
/// Set when a password sign-in route (<c>POST /login</c> or JWT <c>POST /create</c>) is mapped.
/// Sign-up and recovery do not set it.
/// The marker is stored on <see cref="IHostEnvironment"/> so a request scope sees the same flag
/// as the root provider used at map time.
/// </summary>
internal static class PasswordSignInMap
{
    private static readonly ConditionalWeakTable<object, Marker> Markers = new();

    public static void Mark(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Markers.GetOrCreateValue(Key(services)).Mapped = true;
    }

    public static bool IsMapped(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        return Markers.TryGetValue(Key(services), out var marker) && marker.Mapped;
    }

    private static object Key(IServiceProvider services)
    {
        return (object?)services.GetService<IHostEnvironment>() ?? services;
    }

    private sealed class Marker
    {
        public bool Mapped { get; set; }
    }
}
