namespace AuthEndpoints.Passkey;

public record PasskeyVerifyAndStoreRequest(string CredentialJson, string? Name = null);

public record PasskeyRenameRequest(string Id, string NewName);

public record PasskeyRegisterOptionsRequest(string Email);

public record PasskeyRequestOptionsRequest(string? Email = null);

public record PasskeyRegisterRequest(string Email, string CredentialJson);

public record PasskeyLoginRequest(string CredentialJson);
