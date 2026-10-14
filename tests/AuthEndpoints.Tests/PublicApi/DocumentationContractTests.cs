using System.Text.RegularExpressions;
using AuthEndpoints.OAuth.GitHub;
using AuthEndpoints.OAuth.Google;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Tests.PublicApi;

public class DocumentationContractTests
{
    private static readonly string[] BreakingHeadings =
    [
        "Email-code table gains Purpose",
        "Email-code messages include ReAuth",
        "Confirm identity accepts an email code",
        "authMethods adds emailCode",
        "Email-code cooldown and send cap are per purpose",
        "Per-method sign-in completers are obsolete",
        "JWT `POST /create` runs the shared password pipeline",
        "Password `/login` no longer calls `SignInManager.PasswordSignInAsync` / `TwoFactorAuthenticatorSignInAsync` / `TwoFactorRecoveryCodeSignInAsync`",
        "JWT refresh rotation and body transport",
        "Enumeration-safe responses",
        "External OAuth types live in AuthEndpoints.dll",
        "External.OAuth below 4.0.0 fails the build (AE4000)",
        "OAuthTicketChain is public",
        "List and link routes use AuthEndpoints sign-in schemes",
        "Email code counts as a sign-in method",
        "Provider packages only register handlers",
        "A missing Add* throws at map time",
        "Account-abuse and confirm-identity rate limits are public",
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

        Assert.Contains(
            "This page lists every breaking change from 3.4.1 to 4.0.0 and its migration.",
            guide,
            StringComparison.Ordinal);
        Assert.Contains(
            "`AddAuthEndpoints` keeps the 3.4.1 options and the `AuthEndpointsSignIn` and `EmailCode.Enabled` names. Nothing to migrate there.",
            guide,
            StringComparison.Ordinal);
        Assert.Contains("Opt-in body transport", guide, StringComparison.Ordinal);
        Assert.Contains("Unknown-email password-hash verify", guide, StringComparison.Ordinal);
        Assert.Contains(
            "Facade login does not run the unknown-email hash verify, so an unknown email can return faster than a wrong password.",
            guide,
            StringComparison.Ordinal);
        Assert.Contains("Cookie-mode refresh detects reuse", guide, StringComparison.Ordinal);
        Assert.DoesNotMatch(PlanId, guide);

        var docs = Path.Combine(FindRepoRoot(), "Documentation", "content");
        foreach (var path in Directory.EnumerateFiles(docs, "*.md", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(path);
            Assert.False(PlanId.IsMatch(text), $"{path} still names an internal plan id.");
        }

        foreach (var title in BreakingHeadings)
        {
            var heading = Regex.Match(guide, $"^## {Regex.Escape(title)}$", RegexOptions.Multiline);
            Assert.True(heading.Success, $"Missing heading '{title}'.");

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

    private static readonly Regex PlanId = new(@"\bB(?:[1-9]|1\d|2[0-2])\b", RegexOptions.Compiled);

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
