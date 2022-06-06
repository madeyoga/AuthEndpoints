using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AuthEndpoints.UnitTests;

[TestClass]
public class UnitTest_OptionsConfigurator
{
    private string secret = "1234567890qwerty";

    [TestMethod]
    public void SymmetricKey_AutoCreate_AccessValidationParameters()
    {
        var configurator = new OptionsConfigurator();

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var options = new AuthEndpointsOptions()
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
        };
        
        configurator.PostConfigure("test", options);

        Assert.IsNotNull(options.AccessValidationParameters);
    }

    [TestMethod]
    public void SymmetricKey_AutoCreate_RefreshValidationParameters()
    {
        var configurator = new OptionsConfigurator();

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var options = new AuthEndpointsOptions()
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
        };

        configurator.PostConfigure("test", options);

        Assert.IsNotNull(options.RefreshValidationParameters);
    }
}
