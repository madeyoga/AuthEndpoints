using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using PublicApiGenerator;

namespace AuthEndpoints.External.OAuth.Tests.PublicApi;

public class PackagedPublicApiTests
{
    [Fact]
    public void ExternalOAuth_ForwardsPublicTypesToAuthEndpoints()
    {
        var shim = Assembly.Load("AuthEndpoints.External.OAuth");
        Assert.Equal(new Version(4, 0, 0, 0), shim.GetName().Version);
        Assert.Empty(shim.GetExportedTypes());

        using var stream = File.OpenRead(shim.Location);
        using var pe = new PEReader(stream);
        var reader = pe.GetMetadataReader();
        var forwarded = new List<string>();
        foreach (var handle in reader.ExportedTypes)
        {
            var exported = reader.GetExportedType(handle);
            var assembly = reader.GetAssemblyReference((AssemblyReferenceHandle)exported.Implementation);
            Assert.Equal("AuthEndpoints", reader.GetString(assembly.Name));
            forwarded.Add(reader.GetString(exported.Namespace) + "." + reader.GetString(exported.Name));
        }

        Assert.Equal(
            [
                "AuthEndpoints.External.OAuth.CookieExternalLoginCompleter`1",
                "AuthEndpoints.External.OAuth.ExternalAccountEndpoints`1",
                "AuthEndpoints.External.OAuth.ExternalAuthBuilder",
                "AuthEndpoints.External.OAuth.ExternalAuthEndpointRouteBuilderExtensions",
                "AuthEndpoints.External.OAuth.ExternalAuthEndpoints`1",
                "AuthEndpoints.External.OAuth.ExternalAuthOptions",
                "AuthEndpoints.External.OAuth.ExternalAuthOptionsValidator",
                "AuthEndpoints.External.OAuth.ExternalEmailClaims",
                "AuthEndpoints.External.OAuth.ExternalLoginListItem",
                "AuthEndpoints.External.OAuth.ExternalLoginProvisionResult`1",
                "AuthEndpoints.External.OAuth.ExternalLoginService`1",
                "AuthEndpoints.External.OAuth.IExternalAuthProvider",
                "AuthEndpoints.External.OAuth.IExternalLoginCompleter`1",
                "AuthEndpoints.External.OAuth.JwtExternalLoginCompleter`1",
                "AuthEndpoints.External.OAuth.OAuthTicketChain",
                "AuthEndpoints.External.OAuth.ServiceCollectionExtensions",
            ],
            forwarded.OrderBy(name => name, StringComparer.Ordinal).ToArray());
        Assert.True(typeof(AuthEndpoints.External.OAuth.OAuthTicketChain).IsPublic);
    }

    [Fact]
    public void ProviderPackages_DoNotDefineRemovedMapExtensions()
    {
        Assert.Null(typeof(AuthEndpoints.OAuth.GitHub.GitHubServiceCollectionExtensions).Assembly
            .GetType("AuthEndpoints.OAuth.GitHub.GitHubEndpointRouteBuilderExtensions"));
        Assert.Null(typeof(AuthEndpoints.OAuth.Google.GoogleServiceCollectionExtensions).Assembly
            .GetType("AuthEndpoints.OAuth.Google.GoogleEndpointRouteBuilderExtensions"));
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
