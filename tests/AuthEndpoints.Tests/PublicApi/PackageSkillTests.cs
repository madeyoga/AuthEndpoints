using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace AuthEndpoints.Tests.PublicApi;

/// <summary>
/// The AuthEndpoints package ships skills/authendpoints in the nupkg. These checks keep
/// that skill valid under the Agent Skills format and matched to the package version.
/// </summary>
public class PackageSkillTests
{
    private static readonly string Repo = FindRepoRoot();
    private static readonly string SkillDirectory = Path.Combine(Repo, "skills", "authendpoints");

    [Fact]
    public void Frontmatter_FollowsAgentSkillsFormat()
    {
        var frontmatter = ReadFrontmatter();

        Assert.Equal("authendpoints", Value(frontmatter, "name"));
        Assert.Equal(Path.GetFileName(SkillDirectory), Value(frontmatter, "name"));

        var description = Value(frontmatter, "description");
        Assert.InRange(description.Length, 1, 1024);
    }

    [Fact]
    public void MetadataVersion_MatchesPackageVersion()
    {
        var project = XDocument.Load(Path.Combine(Repo, "src", "AuthEndpoints", "AuthEndpoints.csproj"));
        var packageVersion = project.Descendants("Version").Single().Value.Trim();

        var match = Regex.Match(ReadFrontmatter(), "^metadata:\\s*\\n\\s+version:\\s*\"([^\"]+)\"", RegexOptions.Multiline);
        Assert.True(match.Success, "SKILL.md needs metadata.version.");
        Assert.Equal(packageVersion, match.Groups[1].Value);

        var body = File.ReadAllText(Path.Combine(SkillDirectory, "SKILL.md"));
        Assert.Contains($"| `AuthEndpoints` | {packageVersion} |", body);
    }

    [Fact]
    public void RelativeLinks_Resolve()
    {
        foreach (var file in Directory.EnumerateFiles(SkillDirectory, "*.md", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            foreach (Match link in Regex.Matches(text, "\\]\\(([^)#]+\\.md)\\)"))
            {
                var target = link.Groups[1].Value;
                if (target.Contains("://", StringComparison.Ordinal))
                {
                    continue;
                }

                var resolved = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(file)!, target));
                Assert.True(File.Exists(resolved), $"{Path.GetRelativePath(Repo, file)} links to missing {target}.");
            }
        }
    }

    [Fact]
    public void EveryReference_IsLinkedFromSkill()
    {
        var skill = File.ReadAllText(Path.Combine(SkillDirectory, "SKILL.md"));
        foreach (var file in Directory.EnumerateFiles(Path.Combine(SkillDirectory, "references"), "*.md"))
        {
            var link = $"(references/{Path.GetFileName(file)})";
            Assert.True(skill.Contains(link, StringComparison.Ordinal), $"SKILL.md does not link {link}.");
        }
    }

    private static string ReadFrontmatter()
    {
        var text = File.ReadAllText(Path.Combine(SkillDirectory, "SKILL.md")).ReplaceLineEndings("\n");
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
