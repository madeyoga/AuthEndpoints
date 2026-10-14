using System.Reflection;
using AuthEndpoints.EmailCode;
using AuthEndpoints.External.OAuth;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.OAuth.GitHub;
using AuthEndpoints.Passkey;

namespace AuthEndpoints.Tests.PublicApi;

public class CompatibilityMarkerTests
{
    private static readonly string[] CompositeNames =
    [
        "MapIdentityManagementApi",
        "MapCookieAuthEndpoints",
        "MapBearerAuthEndpoints",
        "MapJwtAuthEndpoints",
        "MapPasskeyEndpoints",
        "MapPasswordEndpoints",
        "MapEmailCodeEndpoints",
        "AddCookieAuthEndpoints",
        "AddBearerAuthEndpoints",
        "AddAuthEndpoints",
        "MapAuthEndpoints",
        "AddPasswordAuth",
        "MapPasswordAuth",
    ];

    [Fact]
    public void ObsoleteMarkers_NameTheSignInCompleterReplacement()
    {
        var markers = ObsoleteMembers(typeof(AuthEndpointsOptions).Assembly).ToArray();
        Assert.NotEmpty(markers);

        foreach (var (member, obsolete) in markers)
        {
            var message = obsolete.Message ?? "";
            if (message.StartsWith("Constructors of types with required members", StringComparison.Ordinal))
            {
                continue;
            }

            Assert.True(
                message.Contains("ISignInCompleter", StringComparison.Ordinal)
                && message.Contains("AddSignInCompleter", StringComparison.Ordinal)
                && message.Contains("Removed in 5.0", StringComparison.Ordinal),
                Display(member) + ": " + message);
        }

        Assert.Contains(markers, pair => pair.Member.Name == "AddCompleter");
        Assert.Contains(markers, pair => pair.Member.Name == "AddEmailCodeSignInCompleter");
        Assert.Contains(markers, pair => pair.Member.Name == "AddPasskeySignInCompleter");
        Assert.Contains(markers, pair => pair.Member == typeof(IExternalLoginCompleter<>));
        Assert.Contains(markers, pair => pair.Member == typeof(IEmailCodeSignInCompleter<>));
        Assert.Contains(markers, pair => pair.Member == typeof(IPasskeySignInCompleter<>));
    }

    [Fact]
    public void Composites_AndPasswordLoginMode_StayCurrent()
    {
        var assembly = typeof(AuthEndpointsOptions).Assembly;
        foreach (var name in CompositeNames)
        {
            var members = assembly.GetTypes()
                .SelectMany(type => type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
                .Where(member => member.Name == name)
                .ToArray();
            Assert.NotEmpty(members);
            Assert.All(members, member => Assert.Null(member.GetCustomAttribute<ObsoleteAttribute>()));
        }

        Assert.Null(typeof(PasswordLoginMode).GetCustomAttribute<ObsoleteAttribute>());
        Assert.Null(typeof(AuthEndpointsSignIn).GetCustomAttribute<ObsoleteAttribute>());
        Assert.Empty(ObsoleteMembers(typeof(GitHubExternalAuthProvider).Assembly));
    }

    private static IEnumerable<(MemberInfo Member, ObsoleteAttribute Obsolete)> ObsoleteMembers(Assembly assembly)
    {
        const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        foreach (var type in assembly.GetTypes())
        {
            var typeObsolete = type.GetCustomAttribute<ObsoleteAttribute>(inherit: false);
            if (typeObsolete is not null)
            {
                yield return (type, typeObsolete);
            }

            foreach (var member in type.GetMembers(flags))
            {
                var obsolete = member.GetCustomAttribute<ObsoleteAttribute>(inherit: false);
                if (obsolete is not null)
                {
                    yield return (member, obsolete);
                }
            }
        }
    }

    private static string Display(MemberInfo member)
    {
        return member.DeclaringType is null
            ? member.Name
            : member.DeclaringType.Name + "." + member.Name;
    }
}
