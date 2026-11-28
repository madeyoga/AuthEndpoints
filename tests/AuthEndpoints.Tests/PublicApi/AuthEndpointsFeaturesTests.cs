using AuthEndpoints;
using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Passkey;
using AuthEndpoints.ReAuth;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests.PublicApi;

/// <summary>
/// Route conditions read one resolved <see cref="AuthEndpointsFeatures"/> record (#476 item 1).
/// These pin which <c>Add*</c> calls turn on which feature, and that every map agrees with it.
/// </summary>
public class AuthEndpointsFeaturesTests
{
    [Fact]
    public void NoModules_EverythingOff()
    {
        var services = new ServiceCollection().BuildServiceProvider();

        Assert.Same(AuthEndpointsFeatures.None, AuthEndpointsFeatures.For(services));
    }

    [Fact]
    public void Features_AreResolvedOncePerProvider()
    {
        using var provider = new ServiceCollection()
            .AddPasswordSignInEndpoints()
            .BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.Same(AuthEndpointsFeatures.For(provider), AuthEndpointsFeatures.For(scope.ServiceProvider));
    }

    [Fact]
    public void AddPasswordEndpoints_TurnsOnTheBundleAndEachPasswordFeature()
    {
        var features = Resolve(services => services.AddPasswordEndpoints());

        Assert.Equal(
            new PasswordFeatures(Bundle: true, CanSignUp: true, CanSignIn: true, CanRecover: true),
            features.Password);
        Assert.Equal(AuthEndpointsFeatures.None.Passkeys, features.Passkeys);
    }

    [Fact]
    public void AddPasswordSignInEndpoints_DoesNotTurnOnTheBundle()
    {
        var features = Resolve(services => services.AddPasswordSignInEndpoints());

        Assert.Equal(
            new PasswordFeatures(Bundle: false, CanSignUp: false, CanSignIn: true, CanRecover: false),
            features.Password);
    }

    [Fact]
    public void AddPasskeyEndpoints_TurnsOnEveryPasskeyFeature()
    {
        var features = Resolve(services => services.AddPasskeyEndpoints<TestAppUser>());

        Assert.Equal(
            new PasskeyFeatures(
                Bundle: true,
                CanSignUp: true,
                CanAuthenticate: true,
                CanRequestRegisterOptions: true,
                CanManage: true),
            features.Passkeys);
        Assert.True(features.Passkeys.CanConfirmIdentity);
        Assert.True(features.Password.Bundle);
        Assert.True(features.Sessions.Cookie);
        Assert.True(features.AccountManagement);
    }

    [Fact]
    public void BuilderAddPasskeys_TurnsOnEachPasskeyFeature_ButNotTheBundle()
    {
        var features = Resolve(services => services.AddAuthEndpoints<TestAppUser>().AddEntityFrameworkStores<TestDbContext>()
            .AddPasskeys(options => options.ServerDomain = "localhost"));

        Assert.False(features.Passkeys.Bundle);
        Assert.True(features.Passkeys.CanSignUp);
        Assert.True(features.Passkeys.CanAuthenticate);
        Assert.True(features.Passkeys.CanRequestRegisterOptions);
        Assert.True(features.Passkeys.CanManage);

        var withoutSignUp = Resolve(services => services.AddAuthEndpoints<TestAppUser>().AddEntityFrameworkStores<TestDbContext>()
            .AddPasskeys(options => options.SignUp = false));
        Assert.False(withoutSignUp.Passkeys.CanSignUp);
        Assert.False(withoutSignUp.Passkeys.CanRequestRegisterOptions);
        Assert.True(withoutSignUp.Passkeys.CanConfirmIdentity);
    }

    public static TheoryData<string, bool> PasskeyConfirmIdentityCases => new()
    {
        { "none", false },
        { "signIn", true },
        { "management", true },
        { "signUp", false },
        { "registerOptions", false },
        { "bundle", true },
    };

    [Theory]
    [MemberData(nameof(PasskeyConfirmIdentityCases))]
    public void Passkeys_CanConfirmIdentity_WhenTheyCanSignInOrBeManaged(string passkeys, bool expected)
    {
        var features = Resolve(services => AddPasskeys(services, passkeys));

        Assert.Equal(expected, features.Passkeys.CanConfirmIdentity);
    }

    [Theory]
    [MemberData(nameof(PasskeyConfirmIdentityCases))]
    public void EveryManagementMap_MapsPasskeyOptions_ExactlyWhenTheFeatureSaysSo(string passkeys, bool expected)
    {
        const string route = "POST /identity/confirmIdentity/passkeyOptions";

        // The building block and the per-session shared map answer the same question.
        var accountManagement = Routes(passkeys, app =>
            app.MapGroup("/identity").MapAccountManagementEndpoints<TestAppUser>());
        var shared = Routes(passkeys, app =>
            app.MapGroup("/identity").MapSharedAuthEndpoints<TestAppUser>());

        Assert.Equal(expected, accountManagement.Contains(route));
        Assert.Equal(expected, shared.Contains(route));
    }

    [Fact]
    public void EmailCode_CanConfirmIdentity_OnlyWithSend()
    {
        var signInOnly = Resolve(services => services.AddAuthEndpointsEntityFrameworkStores<TestAppUser, TestDbContext>().AddEmailCodeSignInEndpoints<TestAppUser>());
        var sendOnly = Resolve(services => services.AddAuthEndpointsEntityFrameworkStores<TestAppUser, TestDbContext>().AddEmailCodeSendEndpoints<TestAppUser>());

        Assert.Equal(new EmailCodeFeatures(CanSend: false, CanSignIn: true), signInOnly.EmailCode);
        Assert.False(signInOnly.EmailCode.CanConfirmIdentity);
        Assert.Equal(new EmailCodeFeatures(CanSend: true, CanSignIn: false), sendOnly.EmailCode);
        Assert.True(sendOnly.EmailCode.CanConfirmIdentity);
    }

    [Fact]
    public void Sessions_AreIndependentOfEachOther()
    {
        var cookie = Resolve(services => services.AddCookieSessionEndpoints());
        var bearer = Resolve(services => services.AddBearerSessionEndpoints());

        Assert.Equal(new SessionFeatures(Cookie: true, IdentityBearer: false), cookie.Sessions);
        Assert.Equal(new SessionFeatures(Cookie: false, IdentityBearer: true), bearer.Sessions);
    }

    [Fact]
    public void Require_ThrowsWithTheAddCallToMake()
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => AuthEndpointsFeatures.Require(false, "AddPasskeyEndpoints", "MapPasskeyEndpoints"));

        Assert.Equal("Call AddPasskeyEndpoints before MapPasskeyEndpoints.", error.Message);
        AuthEndpointsFeatures.Require(true, "AddPasskeyEndpoints", "MapPasskeyEndpoints");
    }

    private static void AddPasskeys(IServiceCollection services, string passkeys)
    {
        switch (passkeys)
        {
            case "none":
                break;
            case "signIn":
                services.AddPasskeySignInEndpoints<TestAppUser>();
                break;
            case "management":
                services.AddPasskeyManagementEndpoints();
                break;
            case "signUp":
                services.AddPasskeySignUpEndpoints<TestAppUser>();
                break;
            case "registerOptions":
                services.AddPasskeyRegisterOptionsEndpoints();
                break;
            case "bundle":
                services.AddPasskeyEndpoints<TestAppUser>();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(passkeys), passkeys, null);
        }
    }

    private static IReadOnlyList<string> Routes(string passkeys, Action<WebApplication> map)
    {
        using var app = RouteSurface.Build(builder =>
        {
            builder.Services
                .AddIdentityApiEndpoints<TestAppUser>(options =>
                    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
                .AddEntityFrameworkStores<TestDbContext>()
                .AddDefaultTokenProviders();
            builder.Services.AddAccountManagementEndpoints();
            AddPasskeys(builder.Services, passkeys);
        }, map);
        return RouteSurface.ListRoutes(app);
    }

    private static AuthEndpointsFeatures Resolve(Action<IServiceCollection> configure)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        configure(services);
        using var provider = services.BuildServiceProvider();
        return AuthEndpointsFeatures.For(provider);
    }
}
