using System.Runtime.CompilerServices;

namespace AuthEndpoints.External.OAuth.Tests.PublicApi;

internal static class VerifyInitializer
{
    [ModuleInitializer]
    public static void Initialize()
    {
        Environment.SetEnvironmentVariable("DiffEngine_Disabled", "true");
    }
}
