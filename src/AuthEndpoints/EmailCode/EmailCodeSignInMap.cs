using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthEndpoints.EmailCode;

internal static class EmailCodeSignInMap
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
