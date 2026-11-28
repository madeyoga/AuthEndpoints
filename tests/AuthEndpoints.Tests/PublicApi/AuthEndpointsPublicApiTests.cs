namespace AuthEndpoints.Tests.PublicApi;

public class AuthEndpointsPublicApiTests
{
    [Fact]
    public Task AuthEndpoints_PublicApi_MatchesSnapshot()
    {
        var api = PublicApiSnapshots.Generate(typeof(AuthEndpointsOptions).Assembly);
        return Verifier.Verify(api);
    }
}

public class EntityFrameworkCorePublicApiTests
{
    [Fact]
    public Task EntityFrameworkCore_PublicApi_MatchesSnapshot()
    {
        var api = PublicApiSnapshots.Generate(typeof(EntityFrameworkCoreServiceCollectionExtensions).Assembly);
        return Verifier.Verify(api);
    }
}
