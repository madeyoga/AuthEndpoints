namespace AuthEndpoints.ReAuth;

public sealed record AuthMethodsResponse(
    bool Password,
    bool Authenticator,
    bool RecoveryCodes,
    bool Passkeys,
    int PasskeyCount);
