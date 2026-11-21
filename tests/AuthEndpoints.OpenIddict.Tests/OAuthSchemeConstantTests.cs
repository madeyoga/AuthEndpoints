using OpenIddict.Validation.AspNetCore;

namespace AuthEndpoints.OpenIddict.Tests;

public class OAuthSchemeConstantTests
{
    [Fact]
    public void RenamedValidationScheme_KeepsItsValue()
    {
#pragma warning disable CS0618
        Assert.Equal(OAuthServerConstants.AccessTokenScheme, OAuthServerServiceCollectionExtensions.ValidationScheme);
#pragma warning restore CS0618
        Assert.Equal(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, OAuthServerConstants.AccessTokenScheme);
    }
}
