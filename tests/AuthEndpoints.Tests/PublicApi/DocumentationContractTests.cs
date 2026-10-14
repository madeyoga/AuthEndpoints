using System.Text.RegularExpressions;
using AuthEndpoints.OAuth.GitHub;
using AuthEndpoints.OAuth.Google;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Tests.PublicApi;

public class DocumentationContractTests
{
    private static readonly string[] BreakingRows =
    [
        "B3", "B4", "B5", "B6", "B7", "B8", "B9", "B10", "B11", "B12",
        "B13", "B16", "B17", "B18", "B19", "B20", "B21", "B22",
    ];

    private static readonly Dictionary<string, (string File, string Prefix)> Snapshots = new(StringComparer.Ordinal)
    {
        ["MapIdentityManagementApi"] = ("PerSessionSharedRouteTests.MapIdentityManagementApi_MatchesRouteTable.verified.txt", "/identity"),
        ["MapCookieAuthEndpoints"] = ("PerSessionSharedRouteTests.MapCookieAuthEndpoints_Matches341RouteTable.verified.txt", "/identity"),
        ["MapBearerAuthEndpoints"] = ("PerSessionSharedRouteTests.MapBearerAuthEndpoints_Matches341RouteTable.verified.txt", "/identity"),
        ["MapJwtAuthEndpoints"] = ("PerSessionSharedRouteTests.MapJwtAuthEndpoints_Matches341RouteTable.verified.txt", "/auth"),
        ["MapPasskeyEndpoints"] = ("PerSessionSharedRouteTests.MapPasskeyEndpoints_Matches341RouteTable.verified.txt", "/account"),
        ["MapPasswordAuthCookie"] = ("PasswordAuthRouteTests.Cookie_PasskeysOff.verified.txt", "/auth"),
        ["MapPasswordAuthCookiePasskeys"] = ("PasswordAuthRouteTests.Cookie_PasskeysOn.verified.txt", "/auth"),
        ["MapPasswordAuthJwt"] = ("PasswordAuthRouteTests.Jwt_PasskeysOff.verified.txt", "/auth"),
        ["MapPasswordAuthJwtPasskeys"] = ("PasswordAuthRouteTests.Jwt_PasskeysOn.verified.txt", "/auth"),
    };

    [Fact]
    public void CompositionTable_MatchesRouteSnapshots()
    {
        var repo = FindRepoRoot();
        var table = File.ReadAllText(Path.Combine(repo, "Documentation", "content", "3.composables", "4.composition.md"));
        var rows = ParseCompositionRows(table);
        Assert.NotEmpty(rows);

        var byComposite = Snapshots.Keys.ToDictionary(key => key, _ => new HashSet<string>(StringComparer.Ordinal));
        foreach (var row in rows)
        {
            Assert.True(
                row.Scope is "per session" or "shared",
                $"Scope '{row.Scope}' on {row.Map} is not per session or shared.");
            Assert.NotEmpty(row.Routes);

            if (row.Composites.Count == 0)
            {
                continue;
            }

            foreach (var composite in row.Composites)
            {
                Assert.True(byComposite.ContainsKey(composite), $"Unknown composite '{composite}' on {row.Map}.");
                foreach (var route in row.Routes)
                {
                    byComposite[composite].Add(route);
                }
            }
        }

        var snapshotDir = Path.Combine(repo, "tests", "AuthEndpoints.Tests", "PublicApi");
        foreach (var (composite, routes) in byComposite)
        {
            var (file, prefix) = Snapshots[composite];
            var expected = ReadSnapshotRoutes(Path.Combine(snapshotDir, file), prefix);
            Assert.Equal(expected.OrderBy(route => route, StringComparer.Ordinal), routes.OrderBy(route => route, StringComparer.Ordinal));
        }
    }

    [Fact]
    public void UpgradeGuide_HasAMigrationStepForEveryShippingBreakingRow()
    {
        var guide = File.ReadAllText(Path.Combine(
            FindRepoRoot(),
            "Documentation",
            "content",
            "2.guides",
            "14.upgrading-to-4.md"));

        Assert.Contains("B1, B2, B14, and B15 are withdrawn", guide, StringComparison.Ordinal);
        Assert.Contains("Opt-in body transport", guide, StringComparison.Ordinal);
        Assert.Contains("Unknown-email password-hash verify", guide, StringComparison.Ordinal);
        Assert.Contains("Facade login has no dummy hash", guide, StringComparison.Ordinal);
        Assert.Contains("B21. Cookie-mode refresh detects reuse", guide, StringComparison.Ordinal);

        foreach (var withdrawn in new[] { "B1", "B2", "B14", "B15" })
        {
            Assert.DoesNotMatch(
                new Regex($@"^## {withdrawn}\b", RegexOptions.Multiline),
                guide);
        }

        foreach (var row in BreakingRows)
        {
            var heading = Regex.Match(guide, $@"^## {row} .*$", RegexOptions.Multiline);
            Assert.True(heading.Success, $"Missing heading for {row}.");

            var start = heading.Index;
            var next = Regex.Match(guide[(start + heading.Length)..], @"^## ", RegexOptions.Multiline);
            var section = next.Success
                ? guide.Substring(start, heading.Length + next.Index)
                : guide[start..];
            Assert.Contains("Migration.", section, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void RecipeFences_Compile()
    {
        _ = typeof(GitHubServiceCollectionExtensions);
        _ = typeof(GoogleServiceCollectionExtensions);
        _ = typeof(SqliteDbContextOptionsBuilderExtensions);

        var repo = FindRepoRoot();
        var docs = Path.Combine(repo, "Documentation");
        var recipes = Directory.EnumerateFiles(docs, "*.md", SearchOption.AllDirectories)
            .SelectMany(path => ExtractRecipes(path))
            .ToList();

        Assert.Equal(5, recipes.Count);

        var references = LoadReferences();
        var parseOptions = CSharpParseOptions.Default.WithLanguageVersion(LanguageVersion.CSharp13);
        var usings = CSharpSyntaxTree.ParseText(WebSdkGlobalUsings, parseOptions);

        var failures = new List<string>();
        for (var index = 0; index < recipes.Count; index++)
        {
            var (path, source) = recipes[index];
            var tree = CSharpSyntaxTree.ParseText(source, parseOptions, path);
            var compilation = CSharpCompilation.Create(
                $"recipe{index}",
                [usings, tree],
                references,
                new CSharpCompilationOptions(
                    OutputKind.ConsoleApplication,
                    nullableContextOptions: NullableContextOptions.Enable));

            var errors = compilation.GetDiagnostics()
                .Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error)
                .Select(diagnostic => diagnostic.ToString())
                .ToList();
            if (errors.Count > 0)
            {
                failures.Add($"{path} recipe {index + 1}:{Environment.NewLine}{string.Join(Environment.NewLine, errors)}");
            }
        }

        Assert.True(failures.Count == 0, string.Join(Environment.NewLine + Environment.NewLine, failures));
    }

    private static List<CompositionRow> ParseCompositionRows(string markdown)
    {
        var rows = new List<CompositionRow>();
        var inTable = false;
        foreach (var line in markdown.Split('\n'))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith('|'))
            {
                if (inTable)
                {
                    break;
                }

                continue;
            }

            if (trimmed.Contains("---", StringComparison.Ordinal))
            {
                inTable = true;
                continue;
            }

            if (!inTable)
            {
                continue;
            }

            var cells = trimmed.Split('|', StringSplitOptions.TrimEntries);
            Assert.True(cells.Length >= 7, $"Composition row has {cells.Length - 2} cells: {trimmed}");
            rows.Add(new CompositionRow(
                cells[2],
                cells[3],
                ParseRoutes(cells[4]),
                ParseComposites(cells[5])));
        }

        return rows;
    }

    private static List<string> ParseRoutes(string cell)
    {
        return Regex.Matches(cell, @"`((?:GET|POST|PATCH|DELETE|PUT) /[^`]+)`")
            .Select(match => match.Groups[1].Value)
            .ToList();
    }

    private static List<string> ParseComposites(string cell)
    {
        if (cell.Trim() == "none")
        {
            return [];
        }

        return Regex.Matches(cell, @"`([^`]+)`")
            .Select(match => match.Groups[1].Value)
            .ToList();
    }

    private static HashSet<string> ReadSnapshotRoutes(string path, string prefix)
    {
        var routes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in File.ReadAllLines(path))
        {
            var match = Regex.Match(line, @"^(GET|POST|PATCH|DELETE|PUT) (\S+)");
            if (!match.Success)
            {
                continue;
            }

            var routePath = match.Groups[2].Value;
            Assert.StartsWith(prefix, routePath, StringComparison.Ordinal);
            routes.Add($"{match.Groups[1].Value} {routePath[prefix.Length..]}");
        }

        Assert.NotEmpty(routes);
        return routes;
    }

    private static List<(string Path, string Source)> ExtractRecipes(string path)
    {
        var text = File.ReadAllText(path);
        return Regex.Matches(text, @"```cs recipe\r?\n(.*?)```", RegexOptions.Singleline)
            .Select(match => (path, match.Groups[1].Value))
            .ToList();
    }

    private static List<MetadataReference> LoadReferences()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") is string trusted)
        {
            foreach (var path in trusted.Split(Path.PathSeparator))
            {
                if (path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && File.Exists(path))
                {
                    paths.Add(path);
                }
            }
        }

        foreach (var dll in Directory.EnumerateFiles(AppContext.BaseDirectory, "*.dll"))
        {
            paths.Add(dll);
        }

        return paths.Select(path => (MetadataReference)MetadataReference.CreateFromFile(path)).ToList();
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "AuthEndpoints.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("AuthEndpoints.sln was not found above the test output directory.");
    }

    private const string WebSdkGlobalUsings = """
        global using System;
        global using System.Collections.Generic;
        global using System.IO;
        global using System.Linq;
        global using System.Net.Http;
        global using System.Threading;
        global using System.Threading.Tasks;
        global using Microsoft.AspNetCore.Builder;
        global using Microsoft.AspNetCore.Hosting;
        global using Microsoft.AspNetCore.Http;
        global using Microsoft.AspNetCore.Routing;
        global using Microsoft.Extensions.Configuration;
        global using Microsoft.Extensions.DependencyInjection;
        global using Microsoft.Extensions.Hosting;
        global using Microsoft.Extensions.Logging;
        """;

    private sealed record CompositionRow(string Map, string Scope, List<string> Routes, List<string> Composites);
}
