using AuthEndpoints.EmailCode;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests;

public class EmailCodeOptionsTests
{
    [Fact]
    public void Defaults_MatchDesign()
    {
        var options = new EmailCodeOptions();

        Assert.Equal(6, options.CodeLength);
        Assert.Equal(TimeSpan.FromMinutes(10), options.CodeLifetime);
        Assert.Equal(5, options.MaxAttempts);
        Assert.Equal(TimeSpan.FromSeconds(60), options.ResendCooldown);
        Assert.Equal(5, options.MaxSendsPerEmail);
        Assert.Equal(TimeSpan.FromHours(1), options.SendWindow);
        Assert.Equal(5, options.SendsPerIpPerMinute);
        Assert.False(options.AllowSignUp);
        Assert.True(options.RequireTwoFactor);
        Assert.Equal(EmailCodeUnconfirmedAccounts.ConfirmAndResetCredentials, options.UnconfirmedAccounts);
        Assert.True(options.CountFailuresTowardLockout);
        Assert.False(options.MagicLink.Enabled);
        Assert.Null(options.MagicLink.LinkUri);
        Assert.Empty(options.MagicLink.AllowedOrigins);
        Assert.Null(options.MagicLink.BuildLinkUrl);
        Assert.True(options.RequireSenderOutsideDevelopment);
        Assert.NotNull(options.ReAuth);
        Assert.True(options.ReAuth.Enabled);
        Assert.Equal(EmailCodeReAuthAvailability.WhenNoOtherProof, options.ReAuth.Availability);
        Assert.Equal(TimeSpan.FromMinutes(5), options.ReAuth.CodeLifetime);
    }

    [Fact]
    public void Validator_AcceptsDefaults_InProduction()
    {
        Assert.False(Validate(new EmailCodeOptions(), production: true).Failed);
        Assert.False(Validate(new EmailCodeOptions(), production: false).Failed);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(11)]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validator_RejectsCodeLength(int length)
    {
        var result = Validate(new EmailCodeOptions { CodeLength = length });
        Assert.True(result.Failed);
        Assert.Contains("CodeLength", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(10)]
    public void Validator_AcceptsCodeLength(int length)
    {
        Assert.False(Validate(new EmailCodeOptions { CodeLength = length }).Failed);
    }

    [Fact]
    public void Validator_RejectsCodeLifetime()
    {
        AssertRejected(o => o.CodeLifetime = TimeSpan.Zero, "CodeLifetime");
        AssertRejected(o => o.CodeLifetime = TimeSpan.FromSeconds(59), "CodeLifetime");
        AssertRejected(o => o.CodeLifetime = TimeSpan.FromMinutes(60) + TimeSpan.FromTicks(1), "CodeLifetime");
        AssertRejected(o => o.CodeLifetime = Timeout.InfiniteTimeSpan, "CodeLifetime");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(60)]
    public void Validator_AcceptsCodeLifetime(int minutes)
    {
        Assert.False(Validate(new EmailCodeOptions { CodeLifetime = TimeSpan.FromMinutes(minutes) }).Failed);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(10)]
    public void Validator_AcceptsReAuthCodeLifetime(int minutes)
    {
        var options = new EmailCodeOptions();
        options.ReAuth.CodeLifetime = TimeSpan.FromMinutes(minutes);
        Assert.False(Validate(options).Failed);
    }

    [Fact]
    public void Validator_RejectsReAuthLifetimeAvailabilityAndNull()
    {
        AssertRejected(o => o.ReAuth.CodeLifetime = TimeSpan.FromSeconds(59), "ReAuth.CodeLifetime");
        AssertRejected(o => o.ReAuth.CodeLifetime = TimeSpan.FromMinutes(10) + TimeSpan.FromTicks(1), "ReAuth.CodeLifetime");
        AssertRejected(o =>
        {
            o.ReAuth.Enabled = false;
            o.ReAuth.CodeLifetime = TimeSpan.Zero;
        }, "ReAuth.CodeLifetime");
        AssertRejected(o => o.ReAuth.Availability = (EmailCodeReAuthAvailability)99, "Availability");
        AssertRejected(o => o.ReAuth = null!, "ReAuth is required");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    [InlineData(-1)]
    public void Validator_RejectsMaxAttempts(int attempts)
    {
        var result = Validate(new EmailCodeOptions { MaxAttempts = attempts });
        Assert.True(result.Failed);
        Assert.Contains("MaxAttempts", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(10)]
    public void Validator_AcceptsMaxAttempts(int attempts)
    {
        Assert.False(Validate(new EmailCodeOptions { MaxAttempts = attempts }).Failed);
    }

    [Fact]
    public void Validator_RejectsResendCooldown()
    {
        AssertRejected(o => o.ResendCooldown = TimeSpan.FromTicks(-1), "ResendCooldown");
        AssertRejected(o => o.ResendCooldown = TimeSpan.FromMinutes(10) + TimeSpan.FromTicks(1), "ResendCooldown");
    }

    [Fact]
    public void Validator_AcceptsResendCooldownBounds()
    {
        Assert.False(Validate(new EmailCodeOptions { ResendCooldown = TimeSpan.Zero }).Failed);
        Assert.False(Validate(new EmailCodeOptions { ResendCooldown = TimeSpan.FromMinutes(10) }).Failed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validator_RejectsMaxSendsPerEmail(int sends)
    {
        var result = Validate(new EmailCodeOptions { MaxSendsPerEmail = sends });
        Assert.True(result.Failed);
        Assert.Contains("MaxSendsPerEmail", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validator_RejectsSendWindow()
    {
        AssertRejected(o => o.SendWindow = TimeSpan.Zero, "SendWindow");
        AssertRejected(o => o.SendWindow = TimeSpan.FromSeconds(-1), "SendWindow");
    }

    [Fact]
    public void Validator_AcceptsSendWindow()
    {
        Assert.False(Validate(new EmailCodeOptions { SendWindow = TimeSpan.FromTicks(1) }).Failed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validator_RejectsSendsPerIpPerMinute(int sends)
    {
        var result = Validate(new EmailCodeOptions { SendsPerIpPerMinute = sends });
        Assert.True(result.Failed);
        Assert.Contains("SendsPerIpPerMinute", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validator_RejectsMissingLinkUriWhenMagicLinkEnabled()
    {
        AssertRejected(o => o.MagicLink.Enabled = true, "LinkUri");
        AssertRejected(o =>
        {
            o.MagicLink.Enabled = true;
            o.MagicLink.LinkUri = "   ";
        }, "LinkUri");
    }

    [Fact]
    public void Validator_RejectsHttpLinkUriInProduction()
    {
        var result = Validate(new EmailCodeOptions
        {
            MagicLink = new EmailCodeMagicLinkOptions
            {
                Enabled = true,
                LinkUri = "http://app.example.com/auth/email-link",
                AllowedOrigins = ["http://app.example.com"]
            }
        }, production: true);

        Assert.True(result.Failed);
        Assert.Contains("https", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validator_RejectsNonAllowlistedOriginInProduction()
    {
        var result = Validate(new EmailCodeOptions
        {
            MagicLink = new EmailCodeMagicLinkOptions
            {
                Enabled = true,
                LinkUri = "https://evil.example/auth/email-link",
                AllowedOrigins = ["https://app.example.com"]
            }
        }, production: true);

        Assert.True(result.Failed);
        Assert.Contains("AllowedOrigins", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validator_AcceptsAllowlistedAbsoluteHttpsInProduction()
    {
        Assert.False(Validate(new EmailCodeOptions
        {
            MagicLink = new EmailCodeMagicLinkOptions
            {
                Enabled = true,
                LinkUri = "https://app.example.com/auth/email-link",
                AllowedOrigins = ["https://app.example.com"]
            }
        }, production: true).Failed);

        Assert.False(Validate(new EmailCodeOptions
        {
            MagicLink = new EmailCodeMagicLinkOptions
            {
                Enabled = true,
                LinkUri = "https://app.example.com/auth/email-link?next=/home",
                AllowedOrigins = ["https://app.example.com"]
            }
        }, production: true).Failed);
    }

    [Theory]
    [InlineData("/auth/email-link")]
    [InlineData("auth/email-link")]
    [InlineData("//app.example.com/auth/email-link")]
    [InlineData("https://app.example.com/auth/email-link#token=already")]
    [InlineData("https://app.example.com/auth/email-link#")]
    public void Validator_RejectsRootedPathAndHash(string linkUri)
    {
        AssertRejected(o =>
        {
            o.MagicLink.Enabled = true;
            o.MagicLink.LinkUri = linkUri;
            o.MagicLink.AllowedOrigins = ["https://app.example.com"];
        }, "#");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Validator_AcceptsRootedLinkUriWhenBuildLinkUrlIsSet(bool production)
    {
        var result = Validate(new EmailCodeOptions
        {
            MagicLink = new EmailCodeMagicLinkOptions
            {
                Enabled = true,
                LinkUri = "/auth/email-link",
                BuildLinkUrl = context => context.LinkUri + "?token=" + context.Token
            }
        }, production);

        Assert.False(result.Failed);
    }

    [Theory]
    [InlineData("auth/email-link")]
    [InlineData("//app.example.com/auth/email-link")]
    [InlineData("/auth/email-link#token")]
    public void Validator_RejectsNonRootedOrHashLinkUriWhenBuildLinkUrlIsSet(string linkUri)
    {
        AssertRejected(o =>
        {
            o.MagicLink.Enabled = true;
            o.MagicLink.LinkUri = linkUri;
            o.MagicLink.BuildLinkUrl = context => context.LinkUri;
        }, "#");
    }

    [Fact]
    public void Validator_BuildLinkUrl_StillChecksAbsoluteUriInProduction()
    {
        var http = Validate(new EmailCodeOptions
        {
            MagicLink = new EmailCodeMagicLinkOptions
            {
                Enabled = true,
                LinkUri = "http://app.example.com/auth/email-link",
                AllowedOrigins = ["https://app.example.com"],
                BuildLinkUrl = context => context.LinkUri
            }
        }, production: true);
        Assert.True(http.Failed);
        Assert.Contains("https", http.FailureMessage, StringComparison.Ordinal);

        var foreign = Validate(new EmailCodeOptions
        {
            MagicLink = new EmailCodeMagicLinkOptions
            {
                Enabled = true,
                LinkUri = "https://evil.example/auth/email-link",
                AllowedOrigins = ["https://app.example.com"],
                BuildLinkUrl = context => context.LinkUri
            }
        }, production: true);
        Assert.True(foreign.Failed);
        Assert.Contains("AllowedOrigins", foreign.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validator_RejectsIllegalLinkUri()
    {
        AssertRejected(o =>
        {
            o.MagicLink.Enabled = true;
            o.MagicLink.LinkUri = "javascript:alert(1)";
        }, "LinkUri");
    }

    [Fact]
    public void Validator_AllowsHttpLinkUriOutsideProduction()
    {
        var result = Validate(new EmailCodeOptions
        {
            MagicLink = new EmailCodeMagicLinkOptions
            {
                Enabled = true,
                LinkUri = "http://app.example.com/auth/email-link"
            }
        }, production: false);

        Assert.False(result.Failed);
    }

    private static void AssertRejected(Action<EmailCodeOptions> change, string expected)
    {
        var options = new EmailCodeOptions();
        change(options);
        var result = Validate(options);
        Assert.True(result.Failed);
        Assert.Contains(expected, result.FailureMessage, StringComparison.Ordinal);
    }

    private static ValidateOptionsResult Validate(EmailCodeOptions options, bool production = false)
    {
        var environment = new StubHostEnvironment(production ? Environments.Production : Environments.Development);
        return new EmailCodeOptionsValidator(environment).Validate(null, options);
    }

    private sealed class StubHostEnvironment : IHostEnvironment
    {
        public StubHostEnvironment(string environmentName)
        {
            EnvironmentName = environmentName;
        }

        public string EnvironmentName { get; set; }

        public string ApplicationName { get; set; } = "AuthEndpoints.Tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
