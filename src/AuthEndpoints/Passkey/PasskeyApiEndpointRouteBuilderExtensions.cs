using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AuthEndpoints.Passkey;

public static class PasskeyApiEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapPasskeyEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var group = endpoints.MapGroup("/passkeys");

        group.MapPost("/creationOptions", PasskeyEndpoints<TUser>.CreationOptions)
            .WithSummary("Generate WebAuthn creation options for the signed-in user.")
            .RequireAuthorization()
            .RequireReauth()
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
            .RequireAntiforgery();

        group.MapPost("/requestOptions", PasskeyEndpoints<TUser>.RequestOptions)
            .WithSummary("Generate WebAuthn request options for passkey login.")
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
            .RequireAntiforgery();

        group.MapPost("/register/options", PasskeyEndpoints<TUser>.RegisterOptions)
            .WithSummary("Generate WebAuthn creation options for passwordless account registration.")
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyObtainOptionsPolicy)
            .RequireAntiforgery();

        group.MapPost("/register", PasskeyEndpoints<TUser>.Register)
            .WithSummary("Create a passwordless account and store the attested passkey.")
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyRegisterPolicy)
            .RequireAntiforgery();

        group.MapPost("/login", PasskeyEndpoints<TUser>.Login)
            .WithSummary("Sign in with a passkey assertion.")
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy)
            .RequireAntiforgery();

        group.MapPost("/", PasskeyEndpoints<TUser>.AddPasskey)
            .WithSummary("Attest and store a passkey on the signed-in account.")
            .RequireAuthorization()
            .RequireReauth()
            .RequireRateLimiting(AuthEndpointsConstants.PasskeyRegisterPolicy)
            .RequireAntiforgery();

        group.MapGet("/", PasskeyEndpoints<TUser>.ListPasskeys)
            .WithSummary("List passkeys for the signed-in user.")
            .RequireAuthorization();

        group.MapPatch("/", PasskeyEndpoints<TUser>.RenamePasskey)
            .WithSummary("Rename a passkey.")
            .RequireAuthorization()
            .RequireReauth()
            .RequireAntiforgery();

        group.MapDelete("/{credentialIdUrl}", PasskeyEndpoints<TUser>.DeletePasskey)
            .WithSummary("Remove a passkey from the signed-in account.")
            .RequireAuthorization()
            .RequireReauth()
            .RequireAntiforgery();

        return group;
    }
}
