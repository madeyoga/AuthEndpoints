using System.Diagnostics;
using System.IO.Compression;
using System.Xml.Linq;

namespace AuthEndpoints.OpenIddict.Tests;

public class OAuthPackageDependencyTests
{
    // The package calls CallerKinds and GetCallerKind, which first shipped in AuthEndpoints 4.3.0
    // (and the antiforgery options from 4.2.0). An older core must be refused at restore.
    [Fact]
    public void Packed_package_requires_AuthEndpoints_4_3_or_later()
    {
        var root = FindRepoRoot();
        var output = Path.Combine(Path.GetTempPath(), "ae-oidc-pack-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(output);
        try
        {
            var project = Path.Combine(root, "src", "AuthEndpoints.OpenIddict", "AuthEndpoints.OpenIddict.csproj");
            var result = Pack(project, output);
            Assert.True(result.ExitCode == 0, result.Text);

            var nupkg = Assert.Single(Directory.GetFiles(output, "AuthEndpoints.OpenIddict.*.nupkg"));
            using var zip = ZipFile.OpenRead(nupkg);
            var nuspec = zip.Entries.Single(entry => entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
            using var reader = nuspec.Open();
            var document = XDocument.Load(reader);
            XNamespace ns = document.Root!.Name.Namespace;
            var dependency = document
                .Descendants(ns + "dependency")
                .Single(element => element.Attribute("id")?.Value == "AuthEndpoints");
            Assert.Equal("[4.3.0, 5.0.0)", dependency.Attribute("version")?.Value);
        }
        finally
        {
            Directory.Delete(output, recursive: true);
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
