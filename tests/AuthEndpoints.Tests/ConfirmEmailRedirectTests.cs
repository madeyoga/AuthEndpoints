using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthEndpoints.Tests;

public class ConfirmEmailRedirectTests
{
    private static readonly HostString LocalHost = new("localhost");
    private static readonly string[] SpaOrigin = ["https://spa.example.com"];

    [Fact]
    public void TryResolve_Unset_ReturnsNull()
    {
        Assert.Null(ConfirmEmailRedirect.TryResolve(null, SpaOrigin, allowHttp: true, "https", LocalHost));
        Assert.Null(ConfirmEmailRedirect.TryResolve("  ", SpaOrigin, allowHttp: true, "https", LocalHost));
    }

    [Fact]
    public void TryResolve_RootedPath_ResolvesAgainstRequestOrigin()
    {
        string? resolved = ConfirmEmailRedirect.TryResolve(
            "/auth/email-confirmed",
            Array.Empty<string>(),
            allowHttp: false,
            "https",
            new HostString("api.example.com:8443"));

        Assert.Equal("https://api.example.com:8443/auth/email-confirmed", resolved);
    }

    [Fact]
    public void TryResolve_AbsoluteAllowlistedHttps_ReturnsUri()
    {
        string? resolved = ConfirmEmailRedirect.TryResolve(
            "https://spa.example.com/auth/email-confirmed",
            SpaOrigin,
            allowHttp: false,
            "http",
            LocalHost);

        Assert.NotNull(resolved);
        var uri = new Uri(resolved);
        Assert.Equal("https", uri.Scheme);
        Assert.Equal("spa.example.com", uri.Host);
        Assert.Equal("/auth/email-confirmed", uri.AbsolutePath);
    }

    [Fact]
    public void TryResolve_HttpAbsolute_AllowedOnlyWhenAllowHttp()
    {
        string[] httpOrigin = ["http://spa.example.com"];
        const string configured = "http://spa.example.com/done";

        Assert.Null(ConfirmEmailRedirect.TryResolve(configured, httpOrigin, allowHttp: false, "https", LocalHost));

        string? allowed = ConfirmEmailRedirect.TryResolve(configured, httpOrigin, allowHttp: true, "https", LocalHost);
        Assert.NotNull(allowed);
        Assert.Equal("http://spa.example.com/done", new Uri(allowed).GetLeftPart(UriPartial.Path).TrimEnd('/'));
    }

    [Fact]
    public void TryResolve_ProtocolRelative_ReturnsNull()
    {
        Assert.Null(ConfirmEmailRedirect.TryResolve(
            "//evil.example/x",
            ["https://evil.example"],
            allowHttp: true,
            "https",
            LocalHost));
    }

    [Fact]
    public void TryResolve_NonHttp_ReturnsNull()
    {
        Assert.Null(ConfirmEmailRedirect.TryResolve("javascript:alert(1)", Array.Empty<string>(), allowHttp: true, "https", LocalHost));
        Assert.Null(ConfirmEmailRedirect.TryResolve(
            "ftp://files.example/x",
            ["ftp://files.example"],
            allowHttp: true,
            "https",
            LocalHost));
    }

    [Fact]
    public void TryResolve_AbsoluteEmptyAllowlist_ReturnsNull()
    {
        Assert.Null(ConfirmEmailRedirect.TryResolve(
            "https://spa.example.com/done",
            Array.Empty<string>(),
            allowHttp: true,
            "https",
            LocalHost));
    }

    [Fact]
    public void TryResolve_OriginMismatch_ReturnsNull()
    {
        Assert.Null(ConfirmEmailRedirect.TryResolve(
            "https://other.example/done",
            SpaOrigin,
            allowHttp: true,
            "https",
            LocalHost));
    }

    [Fact]
    public void WithQuery_OverwritesStatusAndFlow()
    {
        string result = ConfirmEmailRedirect.WithQuery(
            "https://spa.example.com/done?status=old&flow=old&keep=1",
            succeeded: true,
            isChangeEmail: false);

        var query = QueryHelpers.ParseQuery(new Uri(result).Query);
        Assert.Equal("confirmed", (string?)query["status"]);
        Assert.Equal("confirm", (string?)query["flow"]);
        Assert.Equal("1", (string?)query["keep"]);
        Assert.Equal(1, query["status"].Count);
        Assert.Equal(1, query["flow"].Count);
    }

    [Fact]
    public void WithQuery_DoesNotAddUserIdCodeOrEmail()
    {
        string result = ConfirmEmailRedirect.WithQuery(
            "https://spa.example.com/done",
            succeeded: false,
            isChangeEmail: true);

        var query = QueryHelpers.ParseQuery(new Uri(result).Query);
        Assert.Equal("failed", (string?)query["status"]);
        Assert.Equal("change-email", (string?)query["flow"]);
        Assert.False(query.ContainsKey("userId"));
        Assert.False(query.ContainsKey("code"));
        Assert.False(query.ContainsKey("email"));
    }
}
