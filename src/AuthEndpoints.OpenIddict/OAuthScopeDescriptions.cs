using System.Globalization;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.OpenIddict;

/// <summary>One scope as a consent page shows it, in the request culture.</summary>
/// <param name="Name">The scope, as the client asked for it.</param>
/// <param name="DisplayName">A short label from <see cref="OAuthServerOptions.ScopeDefinitions"/>, or <paramref name="Name"/>.</param>
/// <param name="Description">What the client can do with the scope, or <see langword="null"/> when none is configured.</param>
public sealed record OAuthScopeDetail(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("displayName")] string DisplayName,
    [property: JsonPropertyName("description")] string? Description);

/// <summary>
/// Turns scope names into the words the consent card shows. The default reads
/// <see cref="OAuthServerOptions.ScopeDefinitions"/>. Replace it with <c>AddScopeDescriptions&lt;T&gt;()</c>, or register your own
/// before <c>AddOAuthServer</c>, to load the text from a database or resource files.
/// </summary>
public interface IOAuthScopeDescriptions
{
    /// <summary>
    /// One entry per scope in <paramref name="scopes"/>, in the same order, with the text for <paramref name="culture"/>.
    /// Called on every consent card fetch and approval, so cache anything slow.
    /// </summary>
    ValueTask<IReadOnlyList<OAuthScopeDetail>> DescribeAsync(
        IReadOnlyList<string> scopes, CultureInfo culture, CancellationToken cancellationToken);
}

/// <summary>
/// The default <see cref="IOAuthScopeDescriptions"/>: <see cref="OAuthServerOptions.ScopeDefinitions"/>, resolved for the
/// culture, then its parents, then the default text. A scope without a definition is shown by its name.
/// </summary>
public sealed class OptionsOAuthScopeDescriptions(IOptions<OAuthServerOptions> options) : IOAuthScopeDescriptions
{
    public ValueTask<IReadOnlyList<OAuthScopeDetail>> DescribeAsync(
        IReadOnlyList<string> scopes, CultureInfo culture, CancellationToken cancellationToken)
        => ValueTask.FromResult(OAuthScopeDescriptions.Describe(scopes, options.Value.ScopeDefinitions, culture));
}

internal static class OAuthScopeDescriptions
{
    /// <summary>
    /// The definitions resolved for <paramref name="culture"/>: the culture, then its parents, then the default text.
    /// Scopes keep their order; one without a definition is shown by its name.
    /// </summary>
    public static IReadOnlyList<OAuthScopeDetail> Describe(
        IEnumerable<string> scopes, IEnumerable<OAuthScopeDefinition> definitions, CultureInfo culture)
    {
        var byName = new Dictionary<string, OAuthScopeDefinition>(StringComparer.Ordinal);
        foreach (var definition in definitions)
        {
            if (definition.Name is { } name)
            {
                byName.TryAdd(name, definition);
            }
        }

        return scopes
            .Select(scope => byName.TryGetValue(scope, out var definition)
                ? new OAuthScopeDetail(
                    scope,
                    Localized(definition.DisplayNames, culture) ?? NonEmpty(definition.DisplayName) ?? scope,
                    Localized(definition.Descriptions, culture) ?? NonEmpty(definition.Description))
                : new OAuthScopeDetail(scope, scope, null))
            .ToList();
    }

    private static string? Localized(IDictionary<string, string> values, CultureInfo culture)
    {
        if (values.Count == 0)
        {
            return null;
        }

        for (var current = culture; !string.IsNullOrEmpty(current.Name); current = current.Parent)
        {
            if (values.TryGetValue(current.Name, out var value) && NonEmpty(value) is { } text)
            {
                return text;
            }
        }

        return null;
    }

    private static string? NonEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    /// <summary>A culture name .NET knows, such as <c>fr</c> or <c>pt-BR</c>. The invariant culture is not one.</summary>
    public static bool IsCultureName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        try
        {
            return !string.IsNullOrEmpty(CultureInfo.GetCultureInfo(name, predefinedOnly: true).Name);
        }
        catch (CultureNotFoundException)
        {
            return false;
        }
    }
}
