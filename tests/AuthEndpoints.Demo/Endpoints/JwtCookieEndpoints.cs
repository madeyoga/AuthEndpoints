using AuthEndpoints.Demo.Models;
using AuthEndpoints.SimpleJwt;

namespace AuthEndpoints.Demo.Endpoints;

public class JwtCookieEndpoints : JwtCookieEndpointDefinitions<string, MyCustomIdentityUser>
{
    public override void MapEndpoints(WebApplication app)
    {
        app.MapPost("/jwt/cookie/create", Create).WithTags("Json Web Token in HttpOnly Cookie");
        app.MapGet("/jwt/cookie/refresh", Refresh).WithTags("Json Web Token in HttpOnly Cookie");
        app.MapGet("/jwt/cookie/verify", Verify).WithTags("Json Web Token in HttpOnly Cookie");
    }
}
