using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthEndpoints.Tests;

internal sealed class SoftwareWebAuthnAuthenticator
{
    private readonly object _gate = new();
    private readonly Dictionary<string, StoredCredential> _credentials = new(StringComparer.Ordinal);

    public string CreateAttestation(string optionsJson, string origin)
    {
        ArgumentException.ThrowIfNullOrEmpty(optionsJson);
        ArgumentException.ThrowIfNullOrEmpty(origin);

        using var doc = JsonDocument.Parse(optionsJson);
        var root = doc.RootElement;
        var challenge = ReadBuffer(root, "challenge", "Challenge");
        var rpId = ReadRpId(root);
        var userHandle = ReadUserHandle(root);

        var credentialId = RandomNumberGenerator.GetBytes(32);
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var coseKey = EncodeCoseEc2Es256(key);
        var authenticatorData = BuildAuthenticatorData(
            rpId,
            userPresent: true,
            userVerified: true,
            attestedCredentialData: BuildAttestedCredentialData(credentialId, coseKey),
            signCount: 1);

        var credentialJson = BuildCredentialJson(
            credentialId,
            origin,
            challenge,
            type: "webauthn.create",
            response: new Dictionary<string, object?>
            {
                ["clientDataJSON"] = Encode(BuildClientDataJson(origin, challenge, "webauthn.create")),
                ["attestationObject"] = Encode(BuildAttestationObject(authenticatorData)),
                ["transports"] = new[] { "internal" }
            });

        var id = Encode(credentialId);
        lock (_gate)
        {
            _credentials[id] = new StoredCredential
            {
                CredentialId = credentialId,
                UserHandle = userHandle,
                Key = key,
                SignCount = 1,
                RpId = rpId
            };
        }

        return credentialJson;
    }

    public string CreateAssertion(string optionsJson, string origin, string? credentialId = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(optionsJson);
        ArgumentException.ThrowIfNullOrEmpty(origin);

        using var doc = JsonDocument.Parse(optionsJson);
        var root = doc.RootElement;
        var challenge = ReadBuffer(root, "challenge", "Challenge");
        var rpId = TestHelpers.TryGetString(root, "rpId", "RpId") ?? ReadRpId(root);

        StoredCredential stored;
        lock (_gate)
        {
            if (credentialId is not null)
            {
                if (!_credentials.TryGetValue(credentialId, out stored!))
                {
                    throw new InvalidOperationException($"No stored credential '{credentialId}'.");
                }
            }
            else if (_credentials.Count == 1)
            {
                stored = _credentials.Values.Single();
            }
            else
            {
                throw new InvalidOperationException("Pass credentialId when more than one credential is stored.");
            }

            stored.SignCount++;
        }

        var authenticatorData = BuildAuthenticatorData(
            rpId,
            userPresent: true,
            userVerified: true,
            attestedCredentialData: null,
            signCount: stored.SignCount);

        var clientDataJson = BuildClientDataJson(origin, challenge, "webauthn.get");
        var clientDataHash = SHA256.HashData(clientDataJson);
        var signed = new byte[authenticatorData.Length + clientDataHash.Length];
        authenticatorData.CopyTo(signed, 0);
        clientDataHash.CopyTo(signed.AsSpan(authenticatorData.Length));
        var signature = stored.Key.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        return BuildCredentialJson(
            stored.CredentialId,
            origin,
            challenge,
            type: "webauthn.get",
            response: new Dictionary<string, object?>
            {
                ["clientDataJSON"] = Encode(clientDataJson),
                ["authenticatorData"] = Encode(authenticatorData),
                ["signature"] = Encode(signature),
                ["userHandle"] = Encode(stored.UserHandle)
            });
    }

    private static byte[] ReadRpIdHash(string rpId) => SHA256.HashData(Encoding.UTF8.GetBytes(rpId));

    private static byte[] BuildAuthenticatorData(
        string rpId,
        bool userPresent,
        bool userVerified,
        byte[]? attestedCredentialData,
        uint signCount)
    {
        byte flags = 0;
        if (userPresent)
        {
            flags |= 1 << 0;
        }

        if (userVerified)
        {
            flags |= 1 << 2;
        }

        if (attestedCredentialData is not null)
        {
            flags |= 1 << 6;
        }

        var extra = attestedCredentialData ?? [];
        var data = new byte[37 + extra.Length];
        ReadRpIdHash(rpId).CopyTo(data, 0);
        data[32] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(33, 4), signCount);
        extra.CopyTo(data.AsSpan(37));
        return data;
    }

    private static byte[] BuildAttestedCredentialData(byte[] credentialId, byte[] coseKey)
    {
        var data = new byte[16 + 2 + credentialId.Length + coseKey.Length];
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(16, 2), (ushort)credentialId.Length);
        credentialId.CopyTo(data.AsSpan(18));
        coseKey.CopyTo(data.AsSpan(18 + credentialId.Length));
        return data;
    }

    private static byte[] BuildAttestationObject(byte[] authenticatorData)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString("none");
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteTextString("authData");
        writer.WriteByteString(authenticatorData);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeCoseEc2Es256(ECDsa key)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);
        var x = Pad32(parameters.Q.X);
        var y = Pad32(parameters.Q.Y);
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(5);
        writer.WriteInt32(1);
        writer.WriteInt32(2);
        writer.WriteInt32(3);
        writer.WriteInt32(-7);
        writer.WriteInt32(-1);
        writer.WriteInt32(1);
        writer.WriteInt32(-2);
        writer.WriteByteString(x);
        writer.WriteInt32(-3);
        writer.WriteByteString(y);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] Pad32(byte[]? value)
    {
        if (value is { Length: 32 })
        {
            return value;
        }

        var padded = new byte[32];
        if (value is { Length: > 0 })
        {
            value.CopyTo(padded, 32 - value.Length);
        }

        return padded;
    }

    private static byte[] BuildClientDataJson(string origin, byte[] challenge, string type)
    {
        var json = JsonSerializer.Serialize(new
        {
            type,
            challenge = Encode(challenge),
            origin,
            crossOrigin = false
        });
        return Encoding.UTF8.GetBytes(json);
    }

    private static string BuildCredentialJson(
        byte[] credentialId,
        string origin,
        byte[] challenge,
        string type,
        Dictionary<string, object?> response)
    {
        _ = origin;
        _ = challenge;
        _ = type;
        var id = Encode(credentialId);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("id", id);
            writer.WriteString("rawId", id);
            writer.WriteString("type", "public-key");
            writer.WriteString("authenticatorAttachment", "platform");
            writer.WriteStartObject("clientExtensionResults");
            writer.WriteEndObject();
            writer.WriteStartObject("response");
            foreach (var (key, value) in response)
            {
                if (value is string s)
                {
                    writer.WriteString(key, s);
                }
                else if (value is string[] arr)
                {
                    writer.WriteStartArray(key);
                    foreach (var item in arr)
                    {
                        writer.WriteStringValue(item);
                    }

                    writer.WriteEndArray();
                }
            }

            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static byte[] ReadBuffer(JsonElement root, string camel, string pascal)
    {
        var encoded = TestHelpers.TryGetString(root, camel, pascal)
            ?? throw new InvalidOperationException($"Missing {camel} in WebAuthn options JSON.");
        return WebEncoders.Base64UrlDecode(encoded);
    }

    private static string ReadRpId(JsonElement root)
    {
        if (root.TryGetProperty("rp", out var rp) || root.TryGetProperty("Rp", out rp))
        {
            return TestHelpers.TryGetString(rp, "id", "Id")
                ?? throw new InvalidOperationException("Missing rp.id in creation options JSON.");
        }

        return TestHelpers.TryGetString(root, "rpId", "RpId")
            ?? throw new InvalidOperationException("Missing rp.id / rpId in WebAuthn options JSON.");
    }

    private static byte[] ReadUserHandle(JsonElement root)
    {
        if (!(root.TryGetProperty("user", out var user) || root.TryGetProperty("User", out user)))
        {
            throw new InvalidOperationException("Missing user in creation options JSON.");
        }

        return ReadBuffer(user, "id", "Id");
    }

    private static string Encode(byte[] bytes) => WebEncoders.Base64UrlEncode(bytes);

    private sealed class StoredCredential
    {
        public required byte[] CredentialId { get; init; }
        public required byte[] UserHandle { get; init; }
        public required ECDsa Key { get; init; }
        public required string RpId { get; init; }
        public uint SignCount { get; set; }
    }
}
