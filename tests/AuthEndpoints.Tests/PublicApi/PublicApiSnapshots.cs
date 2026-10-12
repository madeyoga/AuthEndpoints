using System.Reflection;
using PublicApiGenerator;

namespace AuthEndpoints.Tests.PublicApi;

internal static class PublicApiSnapshots
{
    public static string Generate(Assembly assembly)
    {
        return assembly.GeneratePublicApi(new ApiGeneratorOptions
        {
            IncludeAssemblyAttributes = false,
            TreatRecordsAsClasses = false,
            OrderBy = OrderMode.NamespaceThenFullName,
        });
    }
}
