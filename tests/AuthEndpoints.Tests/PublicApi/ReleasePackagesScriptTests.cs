using System.Diagnostics;
using System.Xml.Linq;

namespace AuthEndpoints.Tests.PublicApi;

/// <summary>
/// .github/scripts/release-packages.sh picks what the publish workflow packs from the release tag (#405).
/// Each family must select only its own projects, and every mismatch must fail before anything is packed.
/// </summary>
public class ReleasePackagesScriptTests
{
    private static readonly string Repo = FindRepoRoot();

    private const string Core = "src/AuthEndpoints/AuthEndpoints.csproj";
    private const string EntityFrameworkCore = "src/AuthEndpoints.EntityFrameworkCore/AuthEndpoints.EntityFrameworkCore.csproj";
    private const string ExternalShim = "src/AuthEndpoints.External.OAuth/AuthEndpoints.External.OAuth.csproj";
    private const string GitHub = "src/AuthEndpoints.OAuth.GitHub/AuthEndpoints.OAuth.GitHub.csproj";
    private const string Google = "src/AuthEndpoints.OAuth.Google/AuthEndpoints.OAuth.Google.csproj";
    private const string OpenIddict = "src/AuthEndpoints.OpenIddict/AuthEndpoints.OpenIddict.csproj";
    private const string OpenIddictEntityFrameworkCore = "src/AuthEndpoints.OpenIddict.EntityFrameworkCore/AuthEndpoints.OpenIddict.EntityFrameworkCore.csproj";

    public static TheoryData<string, string[]> Families => new()
    {
        { "v", [Core, EntityFrameworkCore] },
        { "external-oauth-v", [ExternalShim, GitHub, Google] },
        { "openiddict-v", [OpenIddict, OpenIddictEntityFrameworkCore] },
    };

    [Theory]
    [MemberData(nameof(Families))]
    public void Tag_selects_only_its_own_projects(string prefix, string[] projects)
    {
        var version = Version(projects[0]);
        var result = Run(prefix + version, IsPreRelease(version));

        Assert.True(result.ExitCode == 0, result.Error);
        Assert.Equal(projects, Lines(result.Output));
    }

    [Theory]
    [InlineData("foo-v1.0.0", "no known prefix")]
    [InlineData("1.0.0", "no known prefix")]
    [InlineData("oauth-v1.0.0", "no known prefix")]
    [InlineData("v5.0", "does not end in a version")]
    [InlineData("v05.0.0", "does not end in a version")]
    [InlineData("v5.0.0+build.1", "does not end in a version")]
    [InlineData("openiddict-v", "does not end in a version")]
    public void Unusable_tag_fails(string tag, string message)
    {
        var result = Run(tag, "false");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(message, result.Error);
        Assert.Empty(result.Output);
    }

    [Fact]
    public void Tag_that_differs_from_Version_fails_and_names_every_project()
    {
        var result = Run("external-oauth-v999.0.0", "false");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains($"{ExternalShim} has <Version>{Version(ExternalShim)}</Version>", result.Error);
        Assert.Contains(GitHub, result.Error);
        Assert.Contains(Google, result.Error);
        Assert.Empty(result.Output);
    }

    [Fact]
    public void Prerelease_flag_on_a_stable_version_fails()
    {
        var result = Run("v999.0.0", "true");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("marked pre-release, but 999.0.0 has no pre-release suffix", result.Error);
        Assert.Empty(result.Output);
    }

    [Fact]
    public void Prerelease_version_without_the_flag_fails()
    {
        var result = Run("openiddict-v999.0.0-preview.1", "false");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("not marked pre-release, but 999.0.0-preview.1 has a pre-release suffix", result.Error);
        Assert.Empty(result.Output);
    }

    [Fact]
    public void Prerelease_flag_must_be_true_or_false()
    {
        var result = Run("v999.0.0", "");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("must be true or false", result.Error);
    }

    [Fact]
    public void Every_project_under_src_belongs_to_one_family()
    {
        var packable = Directory
            .GetFiles(Path.Combine(Repo, "src"), "*.csproj", SearchOption.AllDirectories)
            .Where(path => !XDocument.Load(path).Descendants("IsPackable").Any(e => e.Value.Equals("false", StringComparison.OrdinalIgnoreCase)))
            .Select(path => Path.GetRelativePath(Repo, path).Replace('\\', '/'))
            .Order(StringComparer.Ordinal);

        var mapped = Families
            .SelectMany(row => (string[])row[1])
            .Order(StringComparer.Ordinal);

        Assert.Equal(packable, mapped);
    }

    private static string Version(string project)
    {
        return XDocument.Load(Path.Combine(Repo, project)).Descendants("Version").Single().Value;
    }

    private static string IsPreRelease(string version) => version.Contains('-') ? "true" : "false";

    private static string[] Lines(string text)
    {
        return text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static (int ExitCode, string Output, string Error) Run(string tag, string prerelease)
    {
        var start = new ProcessStartInfo
        {
            FileName = "bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = Repo,
        };
        start.ArgumentList.Add(Path.Combine(".github", "scripts", "release-packages.sh"));
        start.ArgumentList.Add(tag);
        start.ArgumentList.Add(prerelease);

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "AuthEndpoints.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException("Could not find AuthEndpoints.sln.");
    }
}
