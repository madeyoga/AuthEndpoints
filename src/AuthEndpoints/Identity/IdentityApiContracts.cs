namespace AuthEndpoints.Identity;

// Request and response bodies for the Identity routes. They replace the Microsoft.AspNetCore.Identity.Data types
// that 4.x exposed, with the same JSON: the same property names, order, and required members.
// AccountInfoResponse.Email is nullable, because Identity allows an account without an email.

/// <summary>Body of password <c>POST /login</c>.</summary>
public sealed class PasswordLoginRequest
{
    public required string Email { get; init; }

    public required string Password { get; init; }

    /// <summary>The authenticator code, when the account has two-factor authentication on.</summary>
    public string? TwoFactorCode { get; init; }

    /// <summary>A recovery code, used instead of <see cref="TwoFactorCode"/>.</summary>
    public string? TwoFactorRecoveryCode { get; init; }
}

/// <summary>Body of <c>POST /register</c>.</summary>
public sealed class PasswordRegisterRequest
{
    public required string Email { get; init; }

    public required string Password { get; init; }
}

/// <summary>Body of Identity bearer <c>POST /refresh</c>.</summary>
public sealed class BearerRefreshRequest
{
    public required string RefreshToken { get; init; }
}

/// <summary>Body of <c>POST /resendConfirmationEmail</c>.</summary>
public sealed class ConfirmationEmailRequest
{
    public required string Email { get; init; }
}

/// <summary>Body of <c>POST /forgotPassword</c>.</summary>
public sealed class PasswordRecoveryRequest
{
    public required string Email { get; init; }
}

/// <summary>Body of <c>POST /resetPassword</c>.</summary>
public sealed class PasswordResetRequest
{
    public required string Email { get; init; }

    /// <summary>The code from the reset email.</summary>
    public required string ResetCode { get; init; }

    public required string NewPassword { get; init; }
}

/// <summary>Body of <c>POST /manage/info</c>. Every member is optional.</summary>
public sealed class AccountInfoRequest
{
    /// <summary>Sends a confirmation link to this address. The email changes when the link is used.</summary>
    public string? NewEmail { get; init; }

    /// <summary>Changes the password. Requires <see cref="OldPassword"/>.</summary>
    public string? NewPassword { get; init; }

    public string? OldPassword { get; init; }
}

/// <summary>Response of <c>GET</c> and <c>POST /manage/info</c>.</summary>
public sealed class AccountInfoResponse
{
    /// <summary>The account's email, or null for an account without one, such as one that signs in by user name.</summary>
    public string? Email { get; init; }

    public required bool IsEmailConfirmed { get; init; }
}

/// <summary>Body of <c>POST /manage/2fa</c>. An empty body reads the current settings.</summary>
public sealed class TwoFactorSettingsRequest
{
    /// <summary>True turns two-factor on (needs <see cref="TwoFactorCode"/>), false turns it off, null leaves it.</summary>
    public bool? Enable { get; init; }

    /// <summary>A code from the authenticator app, required to turn two-factor on.</summary>
    public string? TwoFactorCode { get; init; }

    /// <summary>Generates a new authenticator key and turns two-factor off.</summary>
    public bool ResetSharedKey { get; init; }

    /// <summary>Generates new recovery codes.</summary>
    public bool ResetRecoveryCodes { get; init; }

    /// <summary>Forgets the browser remembered by a two-factor sign-in.</summary>
    public bool ForgetMachine { get; init; }
}

/// <summary>Response of <c>POST /manage/2fa</c>.</summary>
public sealed class TwoFactorSettingsResponse
{
    /// <summary>The authenticator key. Empty unless it was just generated, or two-factor is being turned on.</summary>
    public required string SharedKey { get; init; }

    public required int RecoveryCodesLeft { get; init; }

    /// <summary>New recovery codes. Set only when they were just generated.</summary>
    public string[]? RecoveryCodes { get; init; }

    public required bool IsTwoFactorEnabled { get; init; }

    public required bool IsMachineRemembered { get; init; }
}

/// <summary>Response of <c>GET /manage/2fa</c>.</summary>
public sealed class TwoFactorStatusResponse
{
    public required bool IsTwoFactorEnabled { get; init; }

    public required int RecoveryCodesLeft { get; init; }
}
