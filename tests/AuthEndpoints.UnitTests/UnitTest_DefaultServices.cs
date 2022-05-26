using AuthEndpoints.Services;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthEndpoints.UnitTests;

[TestClass]
public class UnitTest_DefaultServices
{
    private string secret = "1234567890qwerty";
    private JwtSecurityTokenHandler? tokenHandler;

    [TestInitialize]
    public void Setup()
    {
        tokenHandler = new JwtSecurityTokenHandler();
    }

    [TestMethod]
    public void CanCreateSymmetricJwt()
    {
        var jwtFactory = new DefaultJwtFactory(tokenHandler!);

        var createdJwt = jwtFactory.Create(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
            SecurityAlgorithms.HmacSha256,
            new JwtPayload(
                "webapi",
                "webapi",
                null,
                DateTime.UtcNow,
                DateTime.UtcNow.AddMinutes(15)
            )
        );

        Assert.IsNotNull(createdJwt);
    }

    [TestMethod]
    public void CanValidateSymmetricJwt()
    {
        var jwtFactory = new DefaultJwtFactory(tokenHandler!);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

        var createdJwt = jwtFactory.Create(
            key,
            SecurityAlgorithms.HmacSha256,
            new JwtPayload(
                "webapi",
                "webapi",
                null,
                DateTime.UtcNow,
                DateTime.UtcNow.AddMinutes(15)
            )
        );

        var jwtValidator = new DefaultJwtValidator(tokenHandler!);
        var validationParam = new TokenValidationParameters()
        {
            IssuerSigningKey = key,
            ValidIssuer = "webapi",
            ValidAudience = "webapi",
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.Zero,
        };

        Assert.IsTrue(jwtValidator.Validate(createdJwt, validationParam));
    }
}
