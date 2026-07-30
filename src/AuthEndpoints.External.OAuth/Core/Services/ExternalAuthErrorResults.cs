using Microsoft.AspNetCore.Http;

namespace AuthEndpoints.External.OAuth;

internal static class ExternalAuthErrorResults
{
    public static IResult Create(
        HttpContext httpContext,
        ExternalAuthOptions options,
        string error,
        string description,
        int statusCode)
    {
        if (PrefersJson(httpContext))
        {
            return Results.Problem(detail: description, statusCode: statusCode, title: error);
        }

        var path = string.IsNullOrEmpty(options.ErrorPath) ? "/" : options.ErrorPath;
        var separator = path.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        var location =
            $"{path}{separator}error={Uri.EscapeDataString(error)}&error_description={Uri.EscapeDataString(description)}";

        return Results.Redirect(location);
    }

    private static bool PrefersJson(HttpContext httpContext)
    {
        var accept = httpContext.Request.Headers.Accept.ToString();
        if (string.IsNullOrEmpty(accept))
        {
            return false;
        }

        var values = accept.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var jsonIndex = -1;
        var htmlIndex = -1;

        for (var i = 0; i < values.Length; i++)
        {
            var media = values[i].Split(';', 2)[0].Trim();
            if (media.Equals("application/json", StringComparison.OrdinalIgnoreCase)
                || media.Equals("application/problem+json", StringComparison.OrdinalIgnoreCase))
            {
                if (jsonIndex < 0)
                {
                    jsonIndex = i;
                }
            }
            else if (media.Equals("text/html", StringComparison.OrdinalIgnoreCase)
                || media.Equals("application/xhtml+xml", StringComparison.OrdinalIgnoreCase)
                || media.Equals("*/*", StringComparison.OrdinalIgnoreCase))
            {
                // Browsers send */* or text/html; treat as HTML-preferring for OAuth redirects.
                if (htmlIndex < 0 && !media.Equals("*/*", StringComparison.OrdinalIgnoreCase))
                {
                    htmlIndex = i;
                }
            }
        }

        // Default for browser OAuth: redirect (not JSON), even when Accept includes */*.
        if (jsonIndex < 0)
        {
            return false;
        }

        if (htmlIndex < 0)
        {
            // application/json without text/html → JSON (API clients).
            return true;
        }

        return jsonIndex < htmlIndex;
    }
}
