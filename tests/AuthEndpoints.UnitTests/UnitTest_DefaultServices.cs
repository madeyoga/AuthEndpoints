﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthEndpoints.SimpleJwt.Core;
using AuthEndpoints.SimpleJwt.Core.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AuthEndpoints.UnitTests;

[TestClass]
public class UnitTest_DefaultServices
{
    private JwtSecurityTokenHandler? tokenHandler;

    [TestInitialize]
    public void Setup()
    {
        tokenHandler = new JwtSecurityTokenHandler();
    }

    [TestMethod]
    public void CanCreateSymmetricJwt()
    {
        var secret = "qwerty1234567890";
        var options = Options.Create(new SimpleJwtOptions()
        {
            AccessSigningOptions = new JwtSigningOptions()
            {
                SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))
            },

            AccessValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero,
            }
        });
        var tokenGenerator = new AccessTokenGenerator(tokenHandler!,
            options,
            new DefaultClaimsProvider());

        var user = new IdentityUser()
        {
            Id = "1",
            UserName = "test",
            Email = "test@developerblogs.id"
        };

        IList<Claim> claims = new List<Claim>();
        claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
        claims.Add(new Claim(ClaimTypes.Name, user.UserName));
        var id = new ClaimsIdentity(claims);

        var jwt = tokenGenerator.GenerateAccessToken(new ClaimsPrincipal(id));
        Assert.IsNotNull(jwt);
    }

    [TestMethod]
    public void CanValidateSymmetricJwt()
    {
        var secret = "qwerty1234567890";
        var options = Options.Create(new SimpleJwtOptions()
        {
            AccessSigningOptions = new JwtSigningOptions()
            {
                SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))
            },

            AccessValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                ValidateIssuerSigningKey = true,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateActor = false,
                ValidateLifetime = false,
                ClockSkew = TimeSpan.Zero,
            }
        });

        var tokenGenerator = new AccessTokenGenerator(tokenHandler!,
            options,
            new DefaultClaimsProvider());

        var user = new IdentityUser()
        {
            UserName = "test",
            Email = "test@developerblogs.id"
        };

        IList<Claim> claims = new List<Claim>();
        claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
        claims.Add(new Claim(ClaimTypes.Name, user.UserName));
        var id = new ClaimsIdentity(claims);

        var jwt = tokenGenerator.GenerateAccessToken(new ClaimsPrincipal(id));
        Assert.IsNotNull(jwt);

        //var jwtValidator = new DefaultJwtValidator(tokenHandler!);
        //Assert.IsTrue(jwtValidator.Validate(jwt, options.Value.AccessValidationParameters!));
    }
}
