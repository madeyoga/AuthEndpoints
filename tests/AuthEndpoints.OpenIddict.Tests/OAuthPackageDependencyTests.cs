using System.Diagnostics;
using System.IO.Compression;
using System.Xml.Linq;

namespace AuthEndpoints.OpenIddict.Tests;

public class OAuthPackageDependencyTests
{
    // The package calls core API added in 4.2 and 4.3 (CallerKinds, GetCallerKind, the antiforgery
    // options). The range starts at the core it was built against, so an older core is refused at restore,
    // and stops before the next major. See src/AuthEndpoints.DependencyRange.targets.
    [Fact]
    public void Packed_package_requires_the_built_core_up_to_its_next_major()
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
            var coreVersion = XDocument
                .Load(Path.Combine(root, "src", "AuthEndpoints", "AuthEndpoints.csproj"))
                .Descendants("Version")
                .Single()
                .Value;
            var major = int.Parse(coreVersion.Split('.')[0], System.Globalization.CultureInfo.InvariantCulture);
            Assert.Equal($"[{coreVersion}, {major + 1}.0.0)", dependency.Attribute("version")?.Value);
            Assert.True(
                System.Version.Parse(coreVersion.Split('-')[0]) >= new System.Version(4, 3, 0),
                $"Core {coreVersion} is older than 4.3.0, which this package needs.");
        }
        finally
        {
            Directory.Delete(output, recursive: true);
        }
    }

    // The EF Core store package implements the store interfaces of AuthEndpoints.OpenIddict, so it ranges that
    // package the same way: from the version it was built against up to the next major.
    [Fact]
    public void Packed_ef_store_package_requires_the_built_openiddict_package_up_to_its_next_major()
    {
        var root = FindRepoRoot();
        var output = Path.Combine(Path.GetTempPath(), "ae-oidc-ef-pack-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(output);
        try
        {
            var project = Path.Combine(root, "src", "AuthEndpoints.OpenIddict.EntityFrameworkCore", "AuthEndpoints.OpenIddict.EntityFrameworkCore.csproj");
            var result = Pack(project, output);
            Assert.True(result.ExitCode == 0, result.Text);

            var nupkg = Assert.Single(Directory.GetFiles(output, "AuthEndpoints.OpenIddict.EntityFrameworkCore.*.nupkg"));
            using var zip = ZipFile.OpenRead(nupkg);
            var nuspec = zip.Entries.Single(entry => entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
            using var reader = nuspec.Open();
            var document = XDocument.Load(reader);
            XNamespace ns = document.Root!.Name.Namespace;
            var dependencies = document.Descendants(ns + "dependency").ToArray();
            var version = XDocument
                .Load(Path.Combine(root, "src", "AuthEndpoints.OpenIddict", "AuthEndpoints.OpenIddict.csproj"))
                .Descendants("Version")
                .Single()
                .Value;
            var major = int.Parse(version.Split('.')[0], System.Globalization.CultureInfo.InvariantCulture);
            var openIddict = dependencies.Single(element => element.Attribute("id")?.Value == "AuthEndpoints.OpenIddict");
            Assert.Equal($"[{version}, {major + 1}.0.0)", openIddict.Attribute("version")?.Value);
            Assert.Contains(dependencies, element => element.Attribute("id")?.Value == "OpenIddict.EntityFrameworkCore");
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
