using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AuthEndpoints.UnitTests;

[TestClass]
public class UnitTest_OptionsValidator
{
    private string secret = "1234567890qwerty";

    [TestMethod]
    public void Issuer_CannotBeNull()
    {
        OptionsValidator validator = new();

        var result = validator.Validate("test", new AuthEndpointsOptions());

        Assert.IsFalse(result.Succeeded);
    }

    [TestMethod]
    public void Audience_CannotBeNull()
    {
        OptionsValidator validator = new();

        var result = validator.Validate("test", new AuthEndpointsOptions());

        Assert.IsFalse(result.Succeeded);
    }

    [TestMethod]
    public void AccessSigningKey_CannotBeNull()
    {
        OptionsValidator validator = new();

        var result = validator.Validate("test", new AuthEndpointsOptions()
        {
            RefreshSigningOptions = new JwtSigningOptions()
            {
                SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                Algorithm = SecurityAlgorithms.HmacSha256,
                ExpirationMinutes = 120
            },
            Issuer = "webapi",
            Audience = "webapi"
        });

        Assert.IsFalse(result.Succeeded);
    }

    [TestMethod]
    public void RefreshSigningKey_CannotBeNull()
    {
        OptionsValidator validator = new();

        var result = validator.Validate("test", new AuthEndpointsOptions()
        {
            AccessSigningOptions = new JwtSigningOptions()
            {
                SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                Algorithm = SecurityAlgorithms.HmacSha256,
                ExpirationMinutes = 120
            },
            Issuer = "webapi",
            Audience = "webapi"
        });

        Assert.IsFalse(result.Succeeded);
    }

    [TestMethod]
    public void Validate_ValidOptions()
    {
        OptionsValidator validator = new();

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var result = validator.Validate("test", new AuthEndpointsOptions()
        {
            AccessSigningOptions = new JwtSigningOptions()
            {
                SigningKey = key,
                Algorithm = SecurityAlgorithms.HmacSha256,
                ExpirationMinutes = 120
            },
            RefreshSigningOptions = new JwtSigningOptions()
            {
                SigningKey = key,
                Algorithm = SecurityAlgorithms.HmacSha256,
                ExpirationMinutes = 120
            },
            Issuer = "webapi",
            Audience = "webapi"
        });

        Assert.IsTrue(result.Succeeded);
    }
}
