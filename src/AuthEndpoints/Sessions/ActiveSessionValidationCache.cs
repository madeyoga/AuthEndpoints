using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Sessions;

/// <summary>
/// Remembers, per session, when the cookie check last read the session record, so the database is
/// read at most once per <see cref="ActiveSessionOptions.RevalidationInterval"/>. Sessions ended in
/// this process are dropped right away; other servers pick up a revoke within the interval.
/// </summary>
internal sealed class ActiveSessionValidationCache
{
    private const int SweepThreshold = 10_000;

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private readonly IOptionsMonitor<ActiveSessionOptions> _options;

    public ActiveSessionValidationCache(TimeProvider time, IOptionsMonitor<ActiveSessionOptions> options)
    {
        _time = time;
        _options = options;
    }

    private TimeSpan Interval => _options.CurrentValue.RevalidationInterval;

    public bool IsFresh(string id, string userId)
    {
        if (Interval <= TimeSpan.Zero || !_entries.TryGetValue(id, out var entry))
        {
            return false;
        }

        return string.Equals(entry.UserId, userId, StringComparison.Ordinal)
            && _time.GetUtcNow() - entry.CheckedAt < Interval;
    }

    public void MarkValid(string id, string userId)
    {
        if (Interval <= TimeSpan.Zero)
        {
            return;
        }

        if (_entries.Count >= SweepThreshold)
        {
            Sweep();
        }

        _entries[id] = new Entry(userId, _time.GetUtcNow());
    }

    public void Remove(IEnumerable<string> ids)
    {
        foreach (var id in ids)
        {
            _entries.TryRemove(id, out _);
        }
    }

    public void Sweep()
    {
        var cutoff = _time.GetUtcNow() - Interval;
        foreach (var pair in _entries)
        {
            if (pair.Value.CheckedAt <= cutoff)
            {
                _entries.TryRemove(pair);
            }
        }
    }

    private sealed record Entry(string UserId, DateTimeOffset CheckedAt);
}
