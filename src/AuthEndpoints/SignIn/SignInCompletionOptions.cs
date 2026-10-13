namespace AuthEndpoints;

/// <summary>
/// Host-wide sign-in completer selection. A name passed to a sign-in map wins over <see cref="Default"/>.
/// An explicitly registered 3.x per-method completer wins over <see cref="Default"/> when the map passes no name.
/// </summary>
public sealed class SignInCompletionOptions
{
    /// <summary>
    /// Keyed <see cref="ISignInCompleter{TUser}"/> name. <see langword="null"/> keeps the 3.x per-method default.
    /// </summary>
    public string? Default { get; set; }
}
