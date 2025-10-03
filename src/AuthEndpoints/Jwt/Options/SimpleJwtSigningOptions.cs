using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthEndpoints.Jwt;

/// <summary>
/// Signing options for Jwt
/// </summary>
public class SimpleJwtSigningOptions
{
    public enum SigningAlgorithm
    {
        Symmetric,
        Rsa,
        Ecdsa,
        X509
    }

    public SigningAlgorithm Algorithm { get; set; } = SigningAlgorithm.Symmetric;

    public string? AlgorithmOverride { get; set; }

    public string SymmetricKey { get; set; } = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    public RSA? RsaKey { get; set; }
    public ECDsa? EcdsaKey { get; set; }
    public X509Certificate2? Certificate { get; set; }

    public SecurityKey ToSecurityKey()
    {
        return Algorithm switch
        {
            SigningAlgorithm.Symmetric =>
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SymmetricKey)),

            SigningAlgorithm.Rsa =>
                new RsaSecurityKey(RsaKey ?? throw new InvalidOperationException("RSA key required")),

            SigningAlgorithm.Ecdsa =>
                new ECDsaSecurityKey(EcdsaKey ?? throw new InvalidOperationException("ECDsa key required")),

            SigningAlgorithm.X509 =>
                new X509SecurityKey(Certificate ?? throw new InvalidOperationException("Certificate required")),

            _ => throw new NotSupportedException()
        };
    }

    public string GetAlgorithm()
    {
        return AlgorithmOverride ?? Algorithm switch
        {
            SigningAlgorithm.Symmetric => SecurityAlgorithms.HmacSha256,
            SigningAlgorithm.Rsa => SecurityAlgorithms.RsaSha256,
            SigningAlgorithm.Ecdsa => SecurityAlgorithms.EcdsaSha256,
            SigningAlgorithm.X509 => SecurityAlgorithms.RsaSha256,
            _ => throw new NotSupportedException()
        };
    }

    public SigningCredentials ToSigningCredentials() => new (ToSecurityKey(), GetAlgorithm());
}
