using System.Diagnostics;
using System.IO.Compression;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.Loader;

namespace AuthEndpoints.External.OAuth.Tests;

public class ExternalOAuthShimTests
{
    private const string Ae4001 =
        "AuthEndpoints.External.OAuth is merged into AuthEndpoints 4.0. Remove the package reference; no code changes are needed.";

    private const string PreviewGitHub =
        "https://api.nuget.org/v3-flatcontainer/authendpoints.oauth.github/3.0.0-preview.4/authendpoints.oauth.github.3.0.0-preview.4.nupkg";

    [Fact]
    public void AE4001_uses_the_merge_warning_text()
    {
        var project = WriteProject(
            """
            <Project>
              <Import Project="$(Targets)" />
            </Project>
            """,
            ("Targets", TargetsPath("AuthEndpoints.External.OAuth.targets")));

        var result = RunMsBuild(project, "AuthEndpointsExternalOAuthMergedWarning");
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("AE4001", result.Text, StringComparison.Ordinal);
        Assert.Contains(Ae4001, result.Text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("3.0.0-preview.5")]
    [InlineData("3.0.0-preview.4")]
    [InlineData("4.0.0-preview")]
    public void AE4000_rejects_external_oauth_below_4(string version)
    {
        var project = WriteProject(
            """
            <Project>
              <Import Project="$(Targets)" />
              <ItemGroup>
                <PackageReference Include="AuthEndpoints.External.OAuth" Version="$(ExternalVersion)" />
              </ItemGroup>
            </Project>
            """,
            ("Targets", TargetsPath("AuthEndpoints.targets")),
            ("ExternalVersion", version));

        var result = RunMsBuild(project, "AuthEndpointsRejectExternalOAuthPreview");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("AE4000", result.Text, StringComparison.Ordinal);
        Assert.Contains(version, result.Text, StringComparison.Ordinal);
        Assert.Contains("upgrade AuthEndpoints.External.OAuth to 4.0.0", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void AE4000_allows_the_4_0_0_shim()
    {
        var project = WriteProject(
            """
            <Project>
              <Import Project="$(Targets)" />
              <ItemGroup>
                <PackageReference Include="AuthEndpoints.External.OAuth" Version="4.0.0" />
                <PackageVersion Include="AuthEndpoints.External.OAuth" Version="4.0.0" />
              </ItemGroup>
            </Project>
            """,
            ("Targets", TargetsPath("AuthEndpoints.targets")));

        var result = RunMsBuild(project, "AuthEndpointsRejectExternalOAuthPreview");
        Assert.Equal(0, result.ExitCode);
        Assert.DoesNotContain("AE4000", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void AE4000_reads_preview_5_from_project_assets()
    {
        var assets = Path.Combine(Path.GetTempPath(), $"ae-assets-{Guid.NewGuid():N}.json");
        File.WriteAllText(assets, """
            { "libraries": { "AuthEndpoints.External.OAuth/3.0.0-preview.5": {} } }
            """);
        var project = WriteProject(
            """
            <Project>
              <Import Project="$(Targets)" />
            </Project>
            """,
            ("Targets", TargetsPath("AuthEndpoints.targets")),
            ("ProjectAssetsFile", assets));

        var result = RunMsBuild(project, "AuthEndpointsRejectExternalOAuthPreview");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("AE4000", result.Text, StringComparison.Ordinal);
        Assert.Contains("3.0.0-preview.5", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Preview4_GitHub_binary_binds_AddGitHub_to_AuthEndpoints()
    {
        var preview = await PreviewGitHubDllAsync();
        var alc = new ShimLoadContext(
            Path.Combine(AppContext.BaseDirectory, "AuthEndpoints.External.OAuth.dll"),
            Path.Combine(AppContext.BaseDirectory, "AuthEndpoints.dll"),
            preview);
        var github = alc.LoadFromAssemblyPath(preview);
        Assert.Contains(
            github.GetReferencedAssemblies(),
            name => name.Name == "AuthEndpoints.External.OAuth" && name.Version!.Major < 4);

        var add = github.GetType("AuthEndpoints.OAuth.GitHub.GitHubServiceCollectionExtensions")!
            .GetMethod("AddGitHub")!;
        var builderType = add.GetParameters()[0].ParameterType;
        Assert.Equal("AuthEndpoints", builderType.Assembly.GetName().Name);
        Assert.Equal("AuthEndpoints.External.OAuth.ExternalAuthBuilder", builderType.FullName);

        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        var builder = Activator.CreateInstance(builderType, typeof(object), services)!;
        var optionsType = add.GetParameters()[1].ParameterType.GetGenericArguments()[0];
        var configure = Expression.Lambda(
            add.GetParameters()[1].ParameterType,
            Expression.Empty(),
            Expression.Parameter(optionsType, "options")).Compile();
        add.Invoke(null, [builder, configure]);
        Assert.Contains(services, descriptor => descriptor.ServiceType.Name == "IExternalAuthProvider");
    }

    private static string TargetsPath(string fileName)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var external = Path.Combine(dir.FullName, "src", "AuthEndpoints.External.OAuth", "buildTransitive", fileName);
            var core = Path.Combine(dir.FullName, "src", "AuthEndpoints", "buildTransitive", fileName);
            if (File.Exists(external))
            {
                return external;
            }

            if (File.Exists(core))
            {
                return core;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException($"Could not find {fileName}.");
    }

    private static string WriteProject(string xml, params (string Name, string Value)[] properties)
    {
        var dir = Path.Combine(Path.GetTempPath(), $"ae-msbuild-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "guard.proj");
        File.WriteAllText(path, xml);
        File.WriteAllText(
            Path.Combine(dir, "Directory.Build.rsp"),
            string.Join(Environment.NewLine, properties.Select(property => $"-p:{property.Name}={property.Value}")));
        return path;
    }

    private static (int ExitCode, string Text) RunMsBuild(string project, string target)
    {
        var start = new ProcessStartInfo
        {
            FileName = "dotnet",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        start.ArgumentList.Add("msbuild");
        start.ArgumentList.Add(project);
        start.ArgumentList.Add($"-t:{target}");
        start.ArgumentList.Add("-nologo");
        start.ArgumentList.Add("-v:m");
        var rsp = Path.Combine(Path.GetDirectoryName(project)!, "Directory.Build.rsp");
        foreach (var line in File.ReadAllLines(rsp))
        {
            start.ArgumentList.Add(line);
        }

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        return (process.ExitCode, stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult());
    }

    private static async Task<string> PreviewGitHubDllAsync()
    {
        var dll = Path.Combine(Path.GetTempPath(), "ae-preview4", "lib", "net10.0", "AuthEndpoints.OAuth.GitHub.dll");
        if (File.Exists(dll))
        {
            return dll;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(dll)!);
        var nupkg = Path.Combine(Path.GetTempPath(), "ae-preview4", "github.nupkg");
        if (!File.Exists(nupkg) && File.Exists("/tmp/nuget-preview/github.nupkg"))
        {
            File.Copy("/tmp/nuget-preview/github.nupkg", nupkg);
        }

        if (!File.Exists(nupkg))
        {
            using var http = new HttpClient();
            await File.WriteAllBytesAsync(nupkg, await http.GetByteArrayAsync(PreviewGitHub));
        }

        ZipFile.ExtractToDirectory(nupkg, Path.Combine(Path.GetTempPath(), "ae-preview4"), overwriteFiles: true);
        return dll;
    }

    private sealed class ShimLoadContext : AssemblyLoadContext
    {
        private readonly string _shim;
        private readonly string _core;
        private readonly string _preview;

        public ShimLoadContext(string shim, string core, string preview)
            : base(isCollectible: false)
        {
            _shim = shim;
            _core = core;
            _preview = preview;
        }

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            if (assemblyName.Name == "AuthEndpoints.External.OAuth")
            {
                return LoadFromAssemblyPath(_shim);
            }

            if (assemblyName.Name == "AuthEndpoints")
            {
                return LoadFromAssemblyPath(_core);
            }

            if (assemblyName.Name == "AuthEndpoints.OAuth.GitHub")
            {
                return LoadFromAssemblyPath(_preview);
            }

            return null;
        }
    }
}
