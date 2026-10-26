using AuthEndpoints.Jwt;

namespace AuthEndpoints.Tests;

public class SimpleJwtSigningOptionsTests
{
    [Theory]
    [InlineData(SimpleJwtSigningOptions.SigningAlgorithm.Rsa, "RsaKey")]
    [InlineData(SimpleJwtSigningOptions.SigningAlgorithm.Ecdsa, "EcdsaKey")]
    [InlineData(SimpleJwtSigningOptions.SigningAlgorithm.X509, "Certificate")]
    public void ToSecurityKey_WhenKeyIsMissing_NamesThePropertyAndTheAlgorithm(
        SimpleJwtSigningOptions.SigningAlgorithm algorithm,
        string property)
    {
        var options = new SimpleJwtSigningOptions { Algorithm = algorithm };

        var exception = Assert.Throws<InvalidOperationException>(options.ToSecurityKey);

        Assert.Equal(
            $"{property} is required when Algorithm is {algorithm}. " +
            $"Set SimpleJwtOptions.SigningOptions.{property}.",
            exception.Message);
    }
}
