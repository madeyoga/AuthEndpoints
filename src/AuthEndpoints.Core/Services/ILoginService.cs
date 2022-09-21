using System.Security.Claims;

namespace AuthEndpoints.Core.Services;

public interface ILoginService
{
    Task<object> LoginAsync(ClaimsPrincipal user);
}
