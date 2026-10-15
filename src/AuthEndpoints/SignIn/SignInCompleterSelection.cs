namespace AuthEndpoints.SignIn;

/// <summary>
/// Completer name captured when a sign-in map is given <c>session:</c> or <c>completer:</c>.
/// Absent metadata means the 3.x per-method default, unless <see cref="SignInCompletionOptions.Default"/> is set.
/// </summary>
internal sealed class SignInCompleterSelection
{
    public SignInCompleterSelection(string name)
    {
        Name = name;
    }

    public string Name { get; }
}

/// <summary>
/// The sign-in map opted into <see cref="SignInCompletionOptions.Default"/>.
/// Composites that pass the 3.x choice explicitly do not add this marker.
/// </summary>
internal sealed class HonorSignInCompletionDefault;
