﻿using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Core.Services;

/// <summary>
/// Default authenticator. 
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class DefaultAuthenticator<TUser> : IAuthenticator<TUser>
    where TUser : class
{
    private readonly UserManager<TUser> userManager;

    public DefaultAuthenticator(UserManager<TUser> userManager)
    {
        this.userManager = userManager;
    }

    /// <summary>
    /// Use this method to verify a set of credentials. It takes credentials as argument, username and password for the default case.
    /// </summary>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <returns>An instance of TUser if credentials are valid</returns>
    public async Task<TUser?> Authenticate(string username, string password)
    {
        var user = await userManager.FindByNameAsync(username);

        if (user == null)
        {
            return null;
        }

        var correctPassword = await userManager.CheckPasswordAsync(user, password);

        if (!correctPassword)
        {
            return null;
        }

        return user;
    }
}
