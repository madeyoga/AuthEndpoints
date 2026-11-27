using System.Reflection;
using AuthEndpoints.Identity;
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
    ];

    [Fact]
    public void Core_HasNoObsoleteMembers()
    {
        // 5.0 removed every API that 4.x marked "Removed in 5.0". The compiler marks the constructors of types with
        // required members itself; those are not deprecations.
        var markers = ObsoleteMembers(typeof(AuthEndpointsOptions).Assembly)
            .Where(pair => !(pair.Obsolete.Message ?? "").StartsWith("Constructors of types with required members", StringComparison.Ordinal))
            .Select(pair => Display(pair.Member) + ": " + pair.Obsolete.Message)
            .ToArray();

        Assert.Empty(markers);
    }

    [Fact]
    public void AnyCallerScheme_KeepsItsValue()
    {
        Assert.Equal("AuthEndpoints.AnyCaller", AuthEndpointsConstants.AnyCallerScheme);
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
        Assert.Null(typeof(PasskeySignInKind).GetCustomAttribute<ObsoleteAttribute>());
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
