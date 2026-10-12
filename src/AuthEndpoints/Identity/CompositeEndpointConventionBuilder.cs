using Microsoft.AspNetCore.Builder;

namespace AuthEndpoints.Identity;

internal sealed class CompositeEndpointConventionBuilder : IEndpointConventionBuilder
{
    private readonly IEndpointConventionBuilder[] _builders;

    public CompositeEndpointConventionBuilder(params IEndpointConventionBuilder[] builders)
    {
        _builders = builders;
    }

    public void Add(Action<EndpointBuilder> convention)
    {
        foreach (var builder in _builders)
        {
            builder.Add(convention);
        }
    }

    public void Finally(Action<EndpointBuilder> finallyConvention)
    {
        foreach (var builder in _builders)
        {
            builder.Finally(finallyConvention);
        }
    }
}

internal sealed class EmptyEndpointConventionBuilder : IEndpointConventionBuilder
{
    public static readonly EmptyEndpointConventionBuilder Instance = new();

    private EmptyEndpointConventionBuilder()
    {
    }

    public void Add(Action<EndpointBuilder> convention)
    {
    }

    public void Finally(Action<EndpointBuilder> finallyConvention)
    {
    }
}
