using System.IdentityModel.Tokens.Jwt;
using AuthEndpoints.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Services;

/// <summary>
/// Default authenticator. 
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class DefaultAuthenticator<TUser> : IAuthenticator<TUser>
    where TUser : class
{
    private readonly IJwtFactory jwtFactory;
    private readonly IClaimsProvider<TUser> claimsProvider;
    private readonly AuthEndpointsOptions options;
    private readonly UserManager<TUser> userManager;

    public DefaultAuthenticator(UserManager<TUser> userManager,
        IJwtFactory jwtFactory,
        IClaimsProvider<TUser> claimsProvider,
        IOptions<AuthEndpointsOptions> options)
    {
        this.jwtFactory = jwtFactory;
        this.claimsProvider = claimsProvider;
        this.userManager = userManager;
        this.options = options.Value;
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
    /// Use this method to get an access Token and a refresh Token for the given TUser
    /// </summary>
    /// <param name="user"></param>
    /// <returns>An instance of <see cref="AuthenticatedUserResponse"/>, containing an access Token and a refresh Token</returns>
    public Task<AuthenticatedUserResponse> Login(TUser user)
    {
        string accessToken = jwtFactory.Create(
            options.AccessSigningOptions.SigningKey!,
            options.AccessSigningOptions.Algorithm,
            new JwtPayload(
                options.Issuer!,
                options.Audience!,
                claimsProvider.provideAccessClaims(user),
                DateTime.UtcNow,
                DateTime.UtcNow.AddMinutes(options.AccessSigningOptions.ExpirationMinutes)
            )
        );
        string refreshToken = jwtFactory.Create(
            options.RefreshSigningOptions.SigningKey!,
            options.RefreshSigningOptions.Algorithm,
            new JwtPayload(
                options.Issuer!,
                options.Audience!,
                claimsProvider.provideRefreshClaims(user),
                DateTime.UtcNow,
                DateTime.UtcNow.AddMinutes(options.RefreshSigningOptions.ExpirationMinutes)
            )
        );
        return Task.FromResult(new AuthenticatedUserResponse()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
        });
    }
}
