namespace AuthEndpoints.SignIn;

internal sealed class SignInCompleterSelection
{
    public SignInCompleterSelection(string name)
    {
        Name = name;
    }

    public string Name { get; }
}

internal sealed class HonorSignInCompletionDefault;
