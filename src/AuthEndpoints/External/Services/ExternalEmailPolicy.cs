namespace AuthEndpoints.External.OAuth;

internal enum ExternalProvisionKind
{
    Deny = 0,
    UseExistingLogin = 1,
    CreateUser = 2,
    LinkExistingUser = 3,
}

internal readonly record struct ExternalEmailFacts(string? Email, bool Verified, bool LocalEmailConfirmed);

internal readonly record struct ExternalProvisionDecision(ExternalProvisionKind Kind, string? Error, string? ErrorDescription)
{
    public static ExternalProvisionDecision Allow(ExternalProvisionKind kind) => new(kind, null, null);

    public static ExternalProvisionDecision Deny(string error, string description) =>
        new(ExternalProvisionKind.Deny, error, description);
}

/// <summary>
/// Pure provision decision. Auto-link always requires a verified provider email and a
/// confirmed local email, even when <paramref name="requireVerifiedEmail"/> is false.
/// </summary>
internal static class ExternalEmailPolicy
{
    internal static ExternalProvisionDecision Decide(
        string expectedProvider,
        string actualProvider,
        bool hasExistingLogin,
        ExternalEmailFacts email,
        bool hasLocalUser,
        bool requireVerifiedEmail,
        bool autoLinkByEmail)
    {
        if (!string.Equals(expectedProvider, actualProvider, StringComparison.Ordinal))
        {
            return ExternalProvisionDecision.Deny(
                "provider_mismatch",
                "External login provider does not match the callback route.");
        }

        if (hasExistingLogin)
        {
            return ExternalProvisionDecision.Allow(ExternalProvisionKind.UseExistingLogin);
        }

        if (string.IsNullOrEmpty(email.Email))
        {
            return ExternalProvisionDecision.Deny(
                "email_missing",
                "The external provider did not return an email claim.");
        }

        if (!hasLocalUser)
        {
            if (requireVerifiedEmail && !email.Verified)
            {
                return ExternalProvisionDecision.Deny(
                    "email_unverified",
                    "The external provider did not return a verified email.");
            }

            return ExternalProvisionDecision.Allow(ExternalProvisionKind.CreateUser);
        }

        if (!autoLinkByEmail)
        {
            return ExternalProvisionDecision.Deny(
                "auto_link_disabled",
                "A local account with this email already exists. Sign in and link the provider from account settings.");
        }

        if (!email.Verified)
        {
            return ExternalProvisionDecision.Deny(
                "email_unverified",
                "Cannot link to an existing account without a verified email from the provider.");
        }

        if (!email.LocalEmailConfirmed)
        {
            return ExternalProvisionDecision.Deny(
                "email_unconfirmed",
                "Cannot link to an existing account whose email is not confirmed.");
        }

        return ExternalProvisionDecision.Allow(ExternalProvisionKind.LinkExistingUser);
    }
}
