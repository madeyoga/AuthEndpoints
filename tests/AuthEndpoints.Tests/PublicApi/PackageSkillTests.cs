using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace AuthEndpoints.Tests.PublicApi;

/// <summary>
/// Each package ships its skill under skills/&lt;name&gt; in the nupkg. These checks keep
/// every skill valid under the Agent Skills format and matched to its package version.
/// </summary>
public class PackageSkillTests
{
    private static readonly string Repo = FindRepoRoot();

    public static TheoryData<string, string> Skills => new()
    {
        { "authendpoints", "AuthEndpoints" },
        { "authendpoints-openiddict", "AuthEndpoints.OpenIddict" },
    };

    [Theory]
    [MemberData(nameof(Skills))]
    public void Frontmatter_FollowsAgentSkillsFormat(string skill, string project)
    {
        _ = project;
        var frontmatter = ReadFrontmatter(skill);

        var name = Value(frontmatter, "name");
        Assert.Equal(skill, name);
        Assert.Matches("^[a-z0-9]+(-[a-z0-9]+)*$", name);
        Assert.InRange(name.Length, 1, 64);

        var description = Value(frontmatter, "description");
        Assert.InRange(description.Length, 1, 1024);
    }

    [Theory]
    [MemberData(nameof(Skills))]
    public void MetadataVersion_MatchesPackageVersion(string skill, string project)
    {
        var packageVersion = PackageVersion(project);

        var match = Regex.Match(ReadFrontmatter(skill), "^metadata:\\s*\\n\\s+version:\\s*\"([^\"]+)\"", RegexOptions.Multiline);
        Assert.True(match.Success, $"{skill}/SKILL.md needs metadata.version.");
        Assert.Equal(packageVersion, match.Groups[1].Value);
    }

    [Fact]
    public void CorePackageTable_MatchesPackageVersion()
    {
        var body = File.ReadAllText(Path.Combine(SkillDirectory("authendpoints"), "SKILL.md"));
        Assert.Contains($"| `AuthEndpoints` | {PackageVersion("AuthEndpoints")} |", body);
    }

    [Theory]
    [MemberData(nameof(Skills))]
    public void Project_PacksSkill(string skill, string project)
    {
        var text = File.ReadAllText(Path.Combine(Repo, "src", project, $"{project}.csproj"));
        Assert.Contains($"PackagePath=\"skills\\{skill}\\\"", text);
    }

    [Theory]
    [MemberData(nameof(Skills))]
    public void RelativeLinks_Resolve(string skill, string project)
    {
        _ = project;
        var directory = SkillDirectory(skill);
        foreach (var file in Directory.EnumerateFiles(directory, "*.md", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            foreach (Match link in Regex.Matches(text, "\\]\\(([^)#]+\\.md)(#[^)]*)?\\)"))
            {
                var target = link.Groups[1].Value;
                if (target.Contains("://", StringComparison.Ordinal))
                {
                    continue;
                }

                var resolved = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(file)!, target));
                Assert.True(File.Exists(resolved), $"{Path.GetRelativePath(Repo, file)} links to missing {target}.");
                Assert.StartsWith(directory, resolved);
            }
        }
    }

    [Theory]
    [MemberData(nameof(Skills))]
    public void EveryReference_IsLinkedFromSkill(string skill, string project)
    {
        _ = project;
        var directory = SkillDirectory(skill);
        var text = File.ReadAllText(Path.Combine(directory, "SKILL.md"));
        foreach (var file in Directory.EnumerateFiles(Path.Combine(directory, "references"), "*.md"))
        {
            var link = $"(references/{Path.GetFileName(file)})";
            Assert.True(text.Contains(link, StringComparison.Ordinal), $"{skill}/SKILL.md does not link {link}.");
        }
    }

    private static string SkillDirectory(string skill) => Path.Combine(Repo, "skills", skill);

    private static string PackageVersion(string project)
    {
        var document = XDocument.Load(Path.Combine(Repo, "src", project, $"{project}.csproj"));
        return document.Descendants("Version").Single().Value.Trim();
    }

    private static string ReadFrontmatter(string skill)
    {
        var text = File.ReadAllText(Path.Combine(SkillDirectory(skill), "SKILL.md")).ReplaceLineEndings("\n");
        Assert.StartsWith("---\n", text);
        var end = text.IndexOf("\n---\n", 4, StringComparison.Ordinal);
        Assert.True(end > 0, "SKILL.md frontmatter is not closed.");
        return text[4..end];
    }

    private static string Value(string frontmatter, string key)
    {
        var match = Regex.Match(frontmatter, $"^{key}:\\s*\"?(.*?)\"?\\s*$", RegexOptions.Multiline);
        Assert.True(match.Success, $"SKILL.md frontmatter has no {key}.");
        return match.Groups[1].Value;
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
}
