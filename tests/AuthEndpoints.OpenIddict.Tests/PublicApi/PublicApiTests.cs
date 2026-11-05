using PublicApiGenerator;

namespace AuthEndpoints.OpenIddict.Tests.PublicApi;

public class PublicApiTests
{
    [Fact]
    public Task OpenIddict_PublicApi_MatchesSnapshot()
        => Verifier.Verify(typeof(OAuthServerOptions).Assembly.GeneratePublicApi(new ApiGeneratorOptions
        {
            IncludeAssemblyAttributes = false,
            TreatRecordsAsClasses = false,
            OrderBy = OrderMode.NamespaceThenFullName,
        }));

    [Fact]
    public void Core_package_has_no_OpenIddict_dependency()
    {
        var core = typeof(AuthEndpoints.Identity.AntiforgeryRouteBuilderExtensions).Assembly;
        Assert.DoesNotContain(core.GetReferencedAssemblies(), name => name.Name!.StartsWith("OpenIddict", StringComparison.Ordinal));
    }
}
