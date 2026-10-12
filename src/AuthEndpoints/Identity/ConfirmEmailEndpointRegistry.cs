using System.Runtime.CompilerServices;

namespace AuthEndpoints.Identity;

internal static class ConfirmEmailEndpointRegistry
{
    private static readonly ConditionalWeakTable<IServiceProvider, Slot> Slots = new();

    public static bool TryAdd(IServiceProvider services, string name)
    {
        return Slots.GetOrCreateValue(services).TryAdd(name);
    }

    private sealed class Slot
    {
        private readonly HashSet<string> _names = new(StringComparer.Ordinal);
        private readonly object _gate = new();

        public bool TryAdd(string name)
        {
            lock (_gate)
            {
                return _names.Add(name);
            }
        }
    }
}
