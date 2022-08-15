using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using AuthEndpoints.TokenAuth.Tests.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.TokenAuth.Tests.Web;

public class TokenBearerHandler<TKey, TUser, TContext> : AuthenticationHandler<TokenBearerOptions>
    where TKey : class, IEquatable<TKey>
    where TUser : IdentityUser<TKey>
    where TContext : DbContext
{
    private readonly AuthTokenValidator<TKey, TUser, TContext> validator;

    public TokenBearerHandler(IOptionsMonitor<TokenBearerOptions> options,
                              ILoggerFactory logger,
                              UrlEncoder encoder,
                              ISystemClock clock,
                              AuthTokenValidator<TKey, TUser, TContext> validator) : base(options, logger, encoder, clock)
    {
        this.validator = validator;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.ContainsKey("Authorization"))
            return AuthenticateResult.Fail("Unauthorized");

        string authorization = Request.Headers.Authorization.ToString();

        if (string.IsNullOrEmpty(authorization))
        {
            return AuthenticateResult.NoResult();
        }

        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        string token = authorization["Bearer ".Length..].Trim();

        if (string.IsNullOrEmpty(token))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        var validatedToken = await validator.ValidateTokenAsync(token);

        if (validatedToken is null)
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, validatedToken.GetUser!.Id.ToString()!),
            new Claim(ClaimTypes.Name, validatedToken.GetUser!.UserName),
            new Claim(ClaimTypes.Email, validatedToken.GetUser!.Email),
        };

        var identity = new ClaimsIdentity(claims, Scheme.Name);

        var ticket = new AuthenticationTicket(new GenericPrincipal(identity, null), Scheme.Name);

        Context.User.AddIdentity(identity);

        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 403;
        return Task.CompletedTask;
    }
}
