using PublicApiGenerator;

namespace AuthEndpoints.External.OAuth.Tests.PublicApi;

public class PackagedPublicApiTests
{
    [Fact]
    public Task ExternalOAuth_PublicApi_MatchesSnapshot()
    {
        return Verifier.Verify(Generate(typeof(AuthEndpoints.External.OAuth.ExternalAuthOptions).Assembly));
    }

    [Fact]
    public Task GitHub_PublicApi_MatchesSnapshot()
    {
        return Verifier.Verify(Generate(typeof(AuthEndpoints.OAuth.GitHub.GitHubServiceCollectionExtensions).Assembly));
    }

    [Fact]
    public Task Google_PublicApi_MatchesSnapshot()
    {
        return Verifier.Verify(Generate(typeof(AuthEndpoints.OAuth.Google.GoogleServiceCollectionExtensions).Assembly));
    }

    private static string Generate(System.Reflection.Assembly assembly)
    {
        return assembly.GeneratePublicApi(new ApiGeneratorOptions
        {
            IncludeAssemblyAttributes = false,
            TreatRecordsAsClasses = false,
            OrderBy = OrderMode.NamespaceThenFullName,
        });
    }
}
