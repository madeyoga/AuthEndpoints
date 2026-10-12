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
