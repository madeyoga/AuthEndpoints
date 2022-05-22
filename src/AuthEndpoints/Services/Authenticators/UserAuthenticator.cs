namespace AuthEndpoints.Services;

using AuthEndpoints.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

/// <summary>
/// Default user authenticator. Use this class to authenticate a user
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class UserAuthenticator<TUser> : IAuthenticator<TUser>
    where TUser : class
{
    private readonly IJwtFactory jwtFactory;
    private readonly IClaimsProvider<TUser> accessClaimsProvider;
    private readonly IClaimsProvider<TUser> refreshClaimsProvider;
    private readonly IOptions<AuthEndpointsOptions> options;
    private readonly UserManager<TUser> userManager;

    public UserAuthenticator(UserManager<TUser> userManager, 
        IJwtFactory jwtFactory, 
        IAccessClaimsProvider<TUser> accessClaimsProvider, 
        IRefreshClaimsProvider<TUser> refreshClaimsProvider,
        IOptions<AuthEndpointsOptions> options)
    {
        this.jwtFactory = jwtFactory;
        this.userManager = userManager;
        this.accessClaimsProvider = accessClaimsProvider;
        this.refreshClaimsProvider = refreshClaimsProvider;
        this.options = options;
    }

    /// <summary>
    /// Use this method to verify a set of credentials. It takes credentials as argument, username and password for the default case.
    /// </summary>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <returns>An instance of TUser if credentials are valid</returns>
    public async Task<TUser?> Authenticate(string username, string password)
    {
        TUser user = await userManager.FindByNameAsync(username);

        if (user == null)
        {
            return null;
        }

        bool correctPassword = await userManager.CheckPasswordAsync(user, password);

        if (!correctPassword)
        {
            return null;
        }

        return user;
    }

    /// <summary>
    /// Use this method to get an access token and a refresh token for the given TUser
    /// </summary>
    /// <param name="user"></param>
    /// <returns>An instance of <see cref="AuthenticatedUserResponse"/>, containing an access token and a refresh token</returns>
    public Task<AuthenticatedUserResponse> Login(TUser user)
    {
        var authEndpointsOptions = options.Value;

        string accessToken = jwtFactory.Create(authEndpointsOptions.AccessSecret!,
            authEndpointsOptions.Issuer!, 
            authEndpointsOptions.Audience!, 
            accessClaimsProvider.provideClaims(user), 
            authEndpointsOptions.AccessExpirationMinutes);

        string refreshToken = jwtFactory.Create(authEndpointsOptions.RefreshSecret!,
            authEndpointsOptions.Issuer!,
            authEndpointsOptions.Audience!,
            refreshClaimsProvider.provideClaims(user),
            authEndpointsOptions.RefreshExpirationMinutes);

        return Task.FromResult(new AuthenticatedUserResponse()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
        });
    }
}
