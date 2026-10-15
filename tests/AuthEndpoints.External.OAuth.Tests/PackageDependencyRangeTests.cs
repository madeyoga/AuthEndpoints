using System.Diagnostics;
using System.IO.Compression;
using System.Xml.Linq;

namespace AuthEndpoints.External.OAuth.Tests;

public class PackageDependencyRangeTests
{
    [Fact]
    public void Packed_packages_depend_on_AuthEndpoints_4()
    {
        var root = FindRepoRoot();
        var output = Path.Combine(Path.GetTempPath(), "ae-pack-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(output);

        string[] projects =
        [
            Path.Combine(root, "src", "AuthEndpoints.External.OAuth", "AuthEndpoints.External.OAuth.csproj"),
            Path.Combine(root, "src", "AuthEndpoints.OAuth.GitHub", "AuthEndpoints.OAuth.GitHub.csproj"),
            Path.Combine(root, "src", "AuthEndpoints.OAuth.Google", "AuthEndpoints.OAuth.Google.csproj"),
        ];

        foreach (var project in projects)
        {
            var result = Pack(project, output);
            Assert.True(result.ExitCode == 0, result.Text);
        }

        var nupkgs = Directory.GetFiles(output, "*.nupkg");
        Assert.Equal(3, nupkgs.Length);

        foreach (var nupkg in nupkgs)
        {
            using var zip = ZipFile.OpenRead(nupkg);
            var nuspec = zip.Entries.Single(entry => entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
            using var reader = nuspec.Open();
            var document = XDocument.Load(reader);
            XNamespace ns = document.Root!.Name.Namespace;
            var dependency = document
                .Descendants(ns + "dependency")
                .Single(element => element.Attribute("id")?.Value == "AuthEndpoints");
            Assert.Equal("[4.0.0, 5.0.0)", dependency.Attribute("version")?.Value);
        }
    }

    private static (int ExitCode, string Text) Pack(string project, string output)
    {
        var start = new ProcessStartInfo
        {
            FileName = "dotnet",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        start.ArgumentList.Add("pack");
        start.ArgumentList.Add(project);
        start.ArgumentList.Add("-o");
        start.ArgumentList.Add(output);
        start.ArgumentList.Add("--nologo");
        start.ArgumentList.Add("-v");
        start.ArgumentList.Add("q");

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        return (process.ExitCode, stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult());
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
