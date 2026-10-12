using System.Runtime.CompilerServices;

namespace AuthEndpoints.Tests.PublicApi;

internal static class VerifyInitializer
{
    [ModuleInitializer]
    public static void Initialize()
    {
        Environment.SetEnvironmentVariable("DiffEngine_Disabled", "true");
    }
}
