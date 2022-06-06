using System.Text;
using Microsoft.Extensions.Logging;
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
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
        });
        OptionsValidator validator = new(loggerFactory.CreateLogger<OptionsValidator>());

        var result = validator.Validate("test", new AuthEndpointsOptions());

        Assert.IsFalse(result.Succeeded);
    }

    [TestMethod]
    public void Audience_CannotBeNull()
    {
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
        });
        OptionsValidator validator = new(loggerFactory.CreateLogger<OptionsValidator>());

        var result = validator.Validate("test", new AuthEndpointsOptions());

        Assert.IsFalse(result.Succeeded);
    }

    [TestMethod]
    public void AccessSigningKey_CannotBeNull()
    {
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
        });
        OptionsValidator validator = new(loggerFactory.CreateLogger<OptionsValidator>());

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
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
        });
        OptionsValidator validator = new(loggerFactory.CreateLogger<OptionsValidator>());

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
    public void ConfiguredOptions_ShouldBeValid()
    {
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
        });
        OptionsValidator validator = new(loggerFactory.CreateLogger<OptionsValidator>());

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var options = new AuthEndpointsOptions()
        {
        };

        OptionsConfigurator configurator = new();
        configurator.PostConfigure("test", options);

        var result = validator.Validate("test", options);

        Assert.IsTrue(result.Succeeded);
    }

    [TestMethod]
    public void Validate_ValidOptions()
    {
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
        });
        OptionsValidator validator = new(loggerFactory.CreateLogger<OptionsValidator>());

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

        var result = validator.Validate("test", new AuthEndpointsOptions()
        {
            AccessSigningOptions = new JwtSigningOptions()
            {
                SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                Algorithm = SecurityAlgorithms.HmacSha256,
                ExpirationMinutes = 120
            },
            RefreshSigningOptions = new JwtSigningOptions()
            {
                SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                Algorithm = SecurityAlgorithms.HmacSha256,
                ExpirationMinutes = 120
            },
            Issuer = "webapi",
            Audience = "webapi",
            AccessValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
            },
            RefreshValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
            },
        });

        Assert.IsTrue(result.Succeeded);
    }
}
