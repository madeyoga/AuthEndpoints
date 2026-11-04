using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace AuthEndpoints.OpenIddict;

/// <summary>Adds signing and encryption credentials from <see cref="OAuthServerCertificateOptions"/>.</summary>
internal static class OAuthServerCertificates
{
    private const string PasswordFile = "oauth-cert-password";
    private const string SigningFile = "oauth-signing.pfx";
    private const string EncryptionFile = "oauth-encryption.pfx";

    public static void Apply(OpenIddictServerOptions server, OAuthServerCertificateOptions options, TimeProvider clock)
    {
        if (options.SigningCertificate is { } signing && options.EncryptionCertificate is { } encryption)
        {
            Add(server, signing, encryption);
            return;
        }

        if (!string.IsNullOrWhiteSpace(options.Path))
        {
            Directory.CreateDirectory(options.Path);
            var password = Password(System.IO.Path.Combine(options.Path, PasswordFile));
            Add(
                server,
                LoadOrCreate(System.IO.Path.Combine(options.Path, SigningFile), password, options.SubjectName + " Signing", encrypt: false, clock),
                LoadOrCreate(System.IO.Path.Combine(options.Path, EncryptionFile), password, options.SubjectName + " Encryption", encrypt: true, clock));
            return;
        }

        if (options.UseEphemeralKeys)
        {
            server.SigningCredentials.Add(new SigningCredentials(
                new RsaSecurityKey(RSA.Create(2048)) { KeyId = Guid.NewGuid().ToString("N") },
                SecurityAlgorithms.RsaSha256));
            server.EncryptionCredentials.Add(new EncryptingCredentials(
                new RsaSecurityKey(RSA.Create(2048)) { KeyId = Guid.NewGuid().ToString("N") },
                SecurityAlgorithms.RsaOAEP,
                SecurityAlgorithms.Aes256CbcHmacSha512));
        }
    }

    private static void Add(OpenIddictServerOptions server, X509Certificate2 signing, X509Certificate2 encryption)
    {
        if (!signing.HasPrivateKey || !encryption.HasPrivateKey)
        {
            throw new InvalidOperationException("The OAuth signing and encryption certificates must have a private key.");
        }

        server.SigningCredentials.Add(new SigningCredentials(new X509SecurityKey(signing), SecurityAlgorithms.RsaSha256));
        server.EncryptionCredentials.Add(new EncryptingCredentials(
            new X509SecurityKey(encryption),
            SecurityAlgorithms.RsaOAEP,
            SecurityAlgorithms.Aes256CbcHmacSha512));
    }

    private static string Password(string path)
    {
        if (File.Exists(path))
        {
            var existing = File.ReadAllText(path).Trim();
            if (existing.Length > 0)
            {
                return existing;
            }
        }

        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        WritePrivate(path, System.Text.Encoding.UTF8.GetBytes(password));
        return password;
    }

    private static X509Certificate2 LoadOrCreate(string path, string password, string subject, bool encrypt, TimeProvider clock)
    {
        var flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;
        if (File.Exists(path))
        {
            return X509CertificateLoader.LoadPkcs12FromFile(path, password, flags);
        }

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(new X500DistinguishedName("CN=" + subject), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var usage = encrypt
            ? X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment
            : X509KeyUsageFlags.DigitalSignature;
        request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, critical: true));
        // NotBefore sits well before any test clock. A certificate dated "yesterday" is still in the future
        // when a test moves the clock back, and OpenIddict then rejects requests.
        var now = clock.GetUtcNow();
        using var generated = request.CreateSelfSigned(now.AddYears(-10), now.AddYears(5));
        WritePrivate(path, generated.Export(X509ContentType.Pfx, password));
        return X509CertificateLoader.LoadPkcs12FromFile(path, password, flags);
    }

    private static void WritePrivate(string path, byte[] bytes)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        using var stream = new FileStream(path, options);
        stream.Write(bytes);
    }
}
