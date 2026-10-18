using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System.Runtime.CompilerServices;

namespace AuthEndpoints.Identity;

internal static class RouteOwnership
{
    private static readonly ConditionalWeakTable<IServiceProvider, Slot> Slots = new();

    public static TBuilder Track<TBuilder>(this TBuilder builder, IEndpointRouteBuilder endpoints, string mapMethod)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrEmpty(mapMethod);

        // Route groups rebuild RouteEndpointBuilder and re-run Finally each time Endpoints is read.
        // The handler builder passed to Track stays the same across those rebuilds.
        builder.Finally(endpointBuilder => Observe(endpoints, endpointBuilder, mapMethod, builder));
        return builder;
    }

    private static void Observe(
        IEndpointRouteBuilder endpoints,
        EndpointBuilder endpointBuilder,
        string mapMethod,
        IEndpointConventionBuilder owner)
    {
        if (endpointBuilder is not RouteEndpointBuilder route)
        {
            return;
        }

        var slot = Slots.GetOrCreateValue(endpoints.ServiceProvider);
        var path = route.RoutePattern.RawText ?? route.RoutePattern.ToString();
        var methods = endpointBuilder.Metadata
            .OfType<IHttpMethodMetadata>()
            .SelectMany(metadata => metadata.HttpMethods)
            .Distinct(StringComparer.Ordinal)
            .DefaultIfEmpty("*")
            .ToArray();

        lock (slot.Gate)
        {
            foreach (var method in methods)
            {
                var key = method + " " + path;
                if (slot.First.TryGetValue(key, out var existing))
                {
                    if (!ReferenceEquals(existing.Owner, owner) && slot.Reported.Add(key))
                    {
                        AuthEndpointsModules.Log(endpoints, $"{existing.MapMethod} and {mapMethod} both map {key}.");
                    }
                }
                else
                {
                    slot.First[key] = (mapMethod, owner);
                }
            }
        }
    }

    private sealed class Slot
    {
        public object Gate { get; } = new();

        public Dictionary<string, (string MapMethod, IEndpointConventionBuilder Owner)> First { get; } =
            new(StringComparer.Ordinal);

        public HashSet<string> Reported { get; } = new(StringComparer.Ordinal);
    }
}
