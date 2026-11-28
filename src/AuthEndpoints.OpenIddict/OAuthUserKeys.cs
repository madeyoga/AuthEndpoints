using System.ComponentModel;
using System.Globalization;

namespace AuthEndpoints.OpenIddict;

/// <summary>Converts the string user ids AuthEndpoints passes around to and from the Identity key type.</summary>
internal static class OAuthUserKeys<TKey>
    where TKey : IEquatable<TKey>
{
    public static bool TryParse(string? value, out TKey key)
    {
        key = default!;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        try
        {
            var converted = TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(value);
            if (converted is TKey typed)
            {
                key = typed;
                return true;
            }
        }
        catch (Exception ex) when (ex is FormatException or NotSupportedException or ArgumentException)
        {
        }

        return false;
    }

    public static string Format(TKey key)
        => Convert.ToString(key, CultureInfo.InvariantCulture) ?? string.Empty;
}
