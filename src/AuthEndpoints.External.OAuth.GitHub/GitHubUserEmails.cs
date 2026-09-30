using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

namespace AuthEndpoints.External.OAuth.GitHub;

/// <summary>
/// Selects a verified GitHub email from <c>GET /user/emails</c>. An unverified primary is ignored.
/// </summary>
internal static class GitHubUserEmails
{
    internal static string? SelectVerified(JsonElement emails)
    {
        if (emails.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        string? fallback = null;
        foreach (var item in emails.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var email = item.TryGetProperty("email", out var emailElement) ? emailElement.GetString() : null;
            if (string.IsNullOrWhiteSpace(email) || !IsTrue(item, "verified"))
            {
                continue;
            }

            if (IsTrue(item, "primary"))
            {
                return email;
            }

            fallback ??= email;
        }

        return fallback;
    }

    internal static async Task ApplyAsync(
        ClaimsIdentity identity,
        HttpClient backchannel,
        string? accessToken,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(backchannel);

        RemoveEmailClaims(identity);
        if (string.IsNullOrEmpty(accessToken))
        {
            return;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user/emails");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        request.Headers.UserAgent.ParseAdd("AuthEndpoints.External.OAuth");

        using var response = await backchannel.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return;
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var selected = SelectVerified(document.RootElement);
        if (string.IsNullOrEmpty(selected))
        {
            return;
        }

        identity.AddClaim(new Claim(ClaimTypes.Email, selected));
        identity.AddClaim(new Claim(ExternalEmailClaims.EmailVerifiedClaimType, "true"));
    }

    private static void RemoveEmailClaims(ClaimsIdentity identity)
    {
        foreach (var claim in identity.FindAll(claim =>
                     claim.Type == ClaimTypes.Email
                     || claim.Type == "email"
                     || claim.Type == ExternalEmailClaims.EmailVerifiedClaimType).ToList())
        {
            identity.RemoveClaim(claim);
        }
    }

    private static bool IsTrue(JsonElement item, string name) =>
        item.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;
}
