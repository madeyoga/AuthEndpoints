using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Passkey;

internal static class PasskeyHttp
{
    public const string InvalidCredentialId = nameof(InvalidCredentialId);
    public const string InvalidPasskeyState = nameof(InvalidPasskeyState);
    public const string UserMismatch = nameof(UserMismatch);
    public const int NameMaxLength = 200;

    public static ValidationProblem Problem(string code, string detail) =>
        TypedResults.ValidationProblem(new Dictionary<string, string[]>
        {
            [code] = [detail]
        });

    public static ValidationProblem InvalidCredentialIdProblem() =>
        Problem(InvalidCredentialId, "The specified passkey ID had an invalid format.");

    public static ValidationProblem InvalidPasskeyStateProblem() =>
        Problem(InvalidPasskeyState, "No passkey ceremony is underway.");

    public static ValidationProblem UserMismatchProblem() =>
        Problem(UserMismatch, "The passkey does not belong to the signed-in user.");

    public static ValidationProblem NameTooLongProblem() =>
        TypedResults.ValidationProblem(new Dictionary<string, string[]>
        {
            ["Name"] = [$"The name must be at most {NameMaxLength} characters."]
        });

    public static bool TryDecodeCredentialId(string? id, [NotNullWhen(true)] out byte[]? credentialId)
    {
        credentialId = null;
        if (string.IsNullOrEmpty(id))
        {
            return false;
        }

        try
        {
            credentialId = Base64Url.DecodeFromChars(id);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    public static string? NormalizeName(string? name, out ValidationProblem? problem)
    {
        problem = null;
        if (name is null)
        {
            return null;
        }

        var trimmed = name.Trim();
        if (trimmed.Length > NameMaxLength)
        {
            problem = NameTooLongProblem();
            return null;
        }

        return trimmed.Length == 0 ? null : trimmed;
    }

    public static bool IsCeremonyNotUnderway(InvalidOperationException exception)
    {
        var message = exception.Message;
        return message.Contains("No passkey attestation is underway", StringComparison.Ordinal)
            || message.Contains("No passkey assertion is underway", StringComparison.Ordinal)
            || message.Contains("Expected passkey operation", StringComparison.Ordinal);
    }

    public static async Task<(T? Result, ValidationProblem? Problem)> TryPerformAsync<T>(
        Func<Task<T>> perform)
        where T : class
    {
        try
        {
            return (await perform(), null);
        }
        catch (InvalidOperationException ex) when (IsCeremonyNotUnderway(ex))
        {
            return (null, InvalidPasskeyStateProblem());
        }
    }

    public static PasskeyCredentialResponse ToCredentialResponse(UserPasskeyInfo passkey) =>
        new(
            Base64Url.EncodeToString(passkey.CredentialId),
            passkey.Name,
            passkey.CreatedAt);
}
