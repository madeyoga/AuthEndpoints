using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Identity;

/// <summary>
/// Logs, at startup, each group of routes a <c>Map*</c> call left out because its feature was not added,
/// and which <c>Add*</c> call maps it (#476 item 2). Paths are relative to the group the map was called on.
/// The category is <see cref="LogCategory"/>, so hosts can raise its level to silence the lines.
/// </summary>
internal static partial class SkippedRoutes
{
    public const string LogCategory = "AuthEndpoints.Routing";

    public static readonly SkippedRoute PasswordSignIn = new(
        "POST /login",
        "password sign-in is not registered. Call AddPassword on AddAuthEndpoints, or AddPasswordSignInEndpoints");

    public static readonly SkippedRoute JwtPasswordSignIn = PasswordSignIn with { Routes = "POST /create" };

    public static readonly SkippedRoute PasswordSignUp = new(
        "POST /register",
        "password sign-up is not registered. Call AddPassword with SignUp on, or AddPasswordSignUpEndpoints");

    public static readonly SkippedRoute PasswordRecovery = new(
        "POST /forgotPassword, POST /resetPassword",
        "password recovery is not registered. Call AddPassword with Recovery on, or AddPasswordRecoveryEndpoints");

    public static readonly SkippedRoute EmailCodeSignIn = new(
        "POST /emailCode/verify",
        "email-code sign-in is not registered. Call AddEmailCode on AddAuthEndpoints, or AddEmailCodeSignInEndpoints");

    public static readonly SkippedRoute EmailCodeSend = new(
        "POST /emailCode/send",
        "email-code send is not registered. Call AddEmailCode on AddAuthEndpoints, or AddEmailCodeSendEndpoints");

    public static readonly SkippedRoute EmailCodeConfirmIdentity = new(
        "POST /confirmIdentity/emailCode/send",
        "email-code send is not registered, so an email code cannot confirm identity. Call AddEmailCode on AddAuthEndpoints, or AddEmailCodeSendEndpoints");

    public static readonly SkippedRoute PasskeySignIn = new(
        "POST /passkeys/requestOptions, POST /passkeys/login",
        "passkey sign-in is not registered. Call AddPasskeys on AddAuthEndpoints, or AddPasskeySignInEndpoints");

    public static readonly SkippedRoute PasskeySignUp = new(
        "POST /passkeys/register",
        "passkey sign-up is not registered. Call AddPasskeys with SignUp on, or AddPasskeySignUpEndpoints");

    public static readonly SkippedRoute PasskeyRegisterOptions = new(
        "POST /passkeys/register/options",
        "passkey sign-up is not registered. Call AddPasskeys with SignUp on, or AddPasskeyRegisterOptionsEndpoints");

    public static readonly SkippedRoute PasskeyManagement = new(
        "GET /passkeys, POST /passkeys/creationOptions, POST /passkeys, PATCH /passkeys, DELETE /passkeys/{credentialIdUrl}",
        "passkey management is not registered. Call AddPasskeys with Management on, or AddPasskeyManagementEndpoints");

    public static readonly SkippedRoute PasskeyConfirmIdentity = new(
        "POST /confirmIdentity/passkeyOptions",
        "passkey sign-in and passkey management are not registered, so a passkey cannot confirm identity. Call AddPasskeys on AddAuthEndpoints, AddPasskeySignInEndpoints, or AddPasskeyManagementEndpoints");

    public static readonly SkippedRoute AccountManagement = new(
        "/manage/* and /confirmIdentity",
        "account management is not registered. Call AddAccountManagementEndpoints");

    public static void Log(IEndpointRouteBuilder endpoints, SkippedRoute skipped)
    {
        var logger = endpoints.ServiceProvider.GetService<ILoggerFactory>()?.CreateLogger(LogCategory);
        if (logger is not null)
        {
            RouteSkipped(logger, skipped.Routes, skipped.Reason);
        }
    }

    [LoggerMessage(
        EventId = 1001,
        EventName = "RouteSkipped",
        Level = LogLevel.Information,
        Message = "Skipped {Routes}: {Reason}.")]
    private static partial void RouteSkipped(ILogger logger, string routes, string reason);
}

internal sealed record SkippedRoute(string Routes, string Reason);
