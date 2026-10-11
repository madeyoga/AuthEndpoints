namespace AuthEndpoints.EmailCode;

internal static class EmailCodeLinks
{
    public static string? CreateUrl(EmailCodeMagicLinkOptions magicLink, string? token)
    {
        ArgumentNullException.ThrowIfNull(magicLink);
        if (!magicLink.Enabled || string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(magicLink.LinkUri))
        {
            return null;
        }

        if (magicLink.BuildLinkUrl is { } build)
        {
            return build(new EmailCodeLinkContext
            {
                Token = token,
                LinkUri = magicLink.LinkUri
            });
        }

        return magicLink.LinkUri + "#token=" + token;
    }
}
