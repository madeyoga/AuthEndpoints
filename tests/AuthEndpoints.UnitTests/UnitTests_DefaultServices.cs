using AuthEndpoints.Services;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthEndpoints.UnitTests;

[TestClass]
public class UnitTests_DefaultServices
{
    private string? createdJwt = null;
    private string? secret = "1234567890qwerty";
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

        createdJwt = jwtFactory.Create(secret!, "webapi", "webapi", null, 15);

        Assert.IsNotNull(createdJwt);
    }

    [TestMethod]
    public void CanValidateSymmetricJwt()
    {
        var jwtFactory = new DefaultJwtFactory(tokenHandler!);

        createdJwt = jwtFactory.Create(secret!, "webapi", "webapi", null, 15);

        var jwtValidator = new DefaultJwtValidator(tokenHandler!);
        var validationParam = new TokenValidationParameters()
        {
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret!)),
            ValidIssuer = "webapi",
            ValidAudience = "webapi",
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.Zero,
        };

        Assert.IsTrue(jwtValidator.Validate(createdJwt, validationParam));
    }
}