using AuthEndpoints.Identity;
using Microsoft.Extensions.Logging;

namespace AuthEndpoints.Tests;

/// <summary>
/// One <see cref="IAccountSecurityNotifier{TUser}"/> method takes every event kind (#476 item 4).
/// The endpoint tests (set password, remove password, register) check which event each route raises.
/// </summary>
public class AccountSecurityNotifierTests
{
    [Theory]
    [InlineData(AccountSecurityEventKind.PasswordSet)]
    [InlineData(AccountSecurityEventKind.PasswordRemoved)]
    [InlineData(AccountSecurityEventKind.RegistrationAttempted)]
    public async Task LoggingNotifier_LogsTheKind_AndNoAddress(AccountSecurityEventKind kind)
    {
        var log = new LogCapture();
        using var provider = Services(log, notifier: true).BuildServiceProvider();
        var notifier = provider.GetRequiredService<IAccountSecurityNotifier<TestAppUser>>();

        await notifier.NotifyAsync(new AccountSecurityEvent<TestAppUser>(kind, new TestAppUser(), "owner@test.local"));

        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Equal(new EventId(1101, "AccountSecurityEventLogged"), entry.EventId);
        Assert.Contains(kind.ToString(), entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("owner@test.local", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LoggingNotifier_HandlesAKindItDoesNotKnow()
    {
        var log = new LogCapture();
        using var provider = Services(log, notifier: true).BuildServiceProvider();
        var notifier = provider.GetRequiredService<IAccountSecurityNotifier<TestAppUser>>();

        await notifier.NotifyAsync(new AccountSecurityEvent<TestAppUser>((AccountSecurityEventKind)999, new TestAppUser(), null));

        Assert.Contains("999", Assert.Single(log.Entries).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnregisteredNotifier_FallsBackToLogging_AndWarns()
    {
        var log = new LogCapture();
        using var provider = Services(log, notifier: false).BuildServiceProvider();
        var securityEvent = new AccountSecurityEvent<TestAppUser>(
            AccountSecurityEventKind.PasswordSet,
            new TestAppUser(),
            "owner@test.local");

        await AccountSecurityNotifications.NotifyAsync(provider, securityEvent, CancellationToken.None);

        Assert.Contains(log.Entries, entry => entry.Level == LogLevel.Warning
            && entry.Message.Contains("IAccountSecurityNotifier<TestAppUser> is not registered", StringComparison.Ordinal));
        Assert.Contains(log.Entries, entry => entry.EventId.Id == 1101);
    }

    [Fact]
    public async Task RegisteredNotifier_ReceivesTheEventAsRaised()
    {
        var mail = new CapturingEmailSender();
        var services = Services(new LogCapture(), notifier: false);
        services.AddSingleton<IAccountSecurityNotifier<TestAppUser>>(mail);
        using var provider = services.BuildServiceProvider();
        var securityEvent = new AccountSecurityEvent<TestAppUser>(
            AccountSecurityEventKind.RegistrationAttempted,
            new TestAppUser(),
            "owner@test.local");

        await AccountSecurityNotifications.NotifyAsync(provider, securityEvent, CancellationToken.None);

        Assert.Same(securityEvent, Assert.Single(mail.SecurityEvents()));
    }

    private static ServiceCollection Services(LogCapture log, bool notifier)
    {
        var services = new ServiceCollection();
        services.AddLogging(logging =>
        {
            logging.ClearProviders();
            logging.SetMinimumLevel(LogLevel.Information);
            logging.AddProvider(log);
        });
        if (notifier)
        {
            services.AddScoped(typeof(IAccountSecurityNotifier<>), typeof(LoggingAccountSecurityNotifier<>));
        }

        return services;
    }

    private sealed record Entry(LogLevel Level, EventId EventId, string Message);

    private sealed class LogCapture : ILoggerProvider
    {
        public List<Entry> Entries { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Logger(Entries);

        public void Dispose()
        {
        }

        private sealed class Logger(List<Entry> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                entries.Add(new Entry(logLevel, eventId, formatter(state, exception)));
            }
        }
    }
}
