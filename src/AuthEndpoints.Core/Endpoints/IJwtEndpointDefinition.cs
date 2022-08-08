using AuthEndpoints.Core.Contracts;
using AuthEndpoints.Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Core.Endpoints;

public interface IJwtEndpointDefinition<TKey, TUser>
    where TKey : IEquatable<TKey>
    where TUser : IdentityUser<TKey>, new()
{
    Task<IResult> Create([FromBody] LoginRequest request, IAuthenticator<TUser> authenticator, UserManager<TUser> userManager);
    Task<IResult> Refresh([FromBody] RefreshRequest request, IRefreshTokenValidator tokenValidator, IOptions<AuthEndpointsOptions> options, UserManager<TUser> userManager, IAccessTokenGenerator<TUser> tokenGenerator);
    Task<IResult> Verify();
}
