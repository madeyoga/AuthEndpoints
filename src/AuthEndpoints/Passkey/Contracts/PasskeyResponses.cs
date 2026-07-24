namespace AuthEndpoints.Passkey;

public record PasskeyCredentialResponse(string CredentialId, string? DisplayName = null);

public record PasskeyListResponse(IReadOnlyList<PasskeyCredentialResponse> Passkeys);
