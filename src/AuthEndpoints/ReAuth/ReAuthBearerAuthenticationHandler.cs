using System.Security.Claims;
using System.Text.Encodings.Web;
using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.ReAuth;

internal sealed class ReAuthBearerAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly ReAuthTokenService _tokenService;

    public ReAuthBearerAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ReAuthTokenService tokenService)
        : base(options, logger, encoder)
    {
        _tokenService = tokenService;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(AuthEndpointsConstants.ReAuthHeaderName, out var headerValues))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var token = headerValues.ToString();
        if (string.IsNullOrWhiteSpace(token))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var principal = _tokenService.Unprotect(token);
        if (principal is null)
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid or expired reauthentication token."));
        }

        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
