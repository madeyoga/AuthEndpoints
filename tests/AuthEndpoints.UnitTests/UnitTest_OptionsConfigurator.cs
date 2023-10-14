using System.Text;
using AuthEndpoints.SimpleJwt;
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
        var configurator = new SimpleJwtOptionsConfigurator();

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var options = new SimpleJwtOptions()
        {
            AccessSigningOptions = new JwtSigningOptions()
            {
                SigningKey = key,
                Algorithm = SecurityAlgorithms.HmacSha256,
                ExpirationMinutes = 120
            },
        };
        
        configurator.PostConfigure("test", options);

        Assert.IsNotNull(options.AccessValidationParameters);
    }
}
