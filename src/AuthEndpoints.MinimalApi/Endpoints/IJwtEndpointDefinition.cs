using AuthEndpoints.Models;
using AuthEndpoints.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.MinimalApi;
public interface IJwtEndpointDefinition<TKey, TUser>
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>, new()
{
    Task<IResult> Create([FromBody] LoginRequest request, IAuthenticator<TUser> authenticator, UserManager<TUser> userManager);
    Task<IResult> Refresh([FromBody] RefreshRequest request, IJwtValidator jwtValidator, IOptions<AuthEndpointsOptions> options, UserManager<TUser> userManager, IAuthenticator<TUser> authenticator);
    IResult Verify();
}
