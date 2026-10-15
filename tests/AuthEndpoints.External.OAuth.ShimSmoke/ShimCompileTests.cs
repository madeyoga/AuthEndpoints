using AuthEndpoints.External.OAuth;

namespace AuthEndpoints.External.OAuth.ShimSmoke;

public class ShimCompileTests
{
    [Fact]
    public void Public_types_compile_against_the_shim_and_resolve_to_AuthEndpoints()
    {
        Assert.Equal("AuthEndpoints", typeof(ExternalAuthOptions).Assembly.GetName().Name);
        Assert.Equal("AuthEndpoints", typeof(OAuthTicketChain).Assembly.GetName().Name);
        Assert.Equal("AuthEndpoints", typeof(ExternalAuthEndpointRouteBuilderExtensions).Assembly.GetName().Name);
        Assert.Equal("AuthEndpoints", typeof(IExternalLoginCompleter<>).Assembly.GetName().Name);
        _ = new ExternalAuthOptions();
    }
}
