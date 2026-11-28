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
    public Task OpenIddictEntityFrameworkCore_PublicApi_MatchesSnapshot()
        => Verifier.Verify(typeof(OAuthServerEntityFrameworkCoreExtensions).Assembly.GeneratePublicApi(new ApiGeneratorOptions
        {
            IncludeAssemblyAttributes = false,
            TreatRecordsAsClasses = false,
            OrderBy = OrderMode.NamespaceThenFullName,
        }));

    // #410: EF Core storage is a separate package, so a host with other storage does not pull in EF Core.
    [Fact]
    public void OpenIddict_package_has_no_EntityFrameworkCore_dependency()
    {
        var package = typeof(OAuthServerOptions).Assembly;
        Assert.DoesNotContain(package.GetReferencedAssemblies(), name =>
            name.Name!.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.Ordinal)
            || name.Name == "OpenIddict.EntityFrameworkCore"
            || name.Name == "AuthEndpoints.EntityFrameworkCore");
    }

    [Fact]
    public void Core_package_has_no_OpenIddict_dependency()
    {
        var core = typeof(AuthEndpoints.Identity.AntiforgeryRouteBuilderExtensions).Assembly;
        Assert.DoesNotContain(core.GetReferencedAssemblies(), name => name.Name!.StartsWith("OpenIddict", StringComparison.Ordinal));
    }
}
