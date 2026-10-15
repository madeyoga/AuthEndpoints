using AuthEndpoints.SignIn;

namespace AuthEndpoints.Tests;

public class SignInMethodPolicyTests
{
    [Theory]
    [InlineData(false, 0, 1, false, true, false)]
    [InlineData(false, 0, 1, true, false, false)]
    [InlineData(false, 0, 1, false, false, false)]
    [InlineData(false, 0, 1, true, true, true)]
    [InlineData(true, 0, 1, false, false, true)]
    [InlineData(false, 1, 1, false, false, true)]
    [InlineData(false, 0, 2, false, false, true)]
    [InlineData(false, 0, 0, true, true, false)]
    public void External_keeps_one_method(
        bool password,
        int passkeys,
        int logins,
        bool emailCodeMapped,
        bool emailConfirmed,
        bool allowed)
    {
        Assert.Equal(allowed, CanRemove(password, passkeys, logins, emailCodeMapped, emailConfirmed, SignInMethod.External));
    }

    [Theory]
    [InlineData(false, 1, 0, false, true, false)]
    [InlineData(false, 1, 0, true, false, false)]
    [InlineData(false, 1, 0, true, true, true)]
    [InlineData(true, 1, 0, false, false, true)]
    [InlineData(false, 2, 0, false, false, true)]
    [InlineData(false, 0, 1, true, true, false)]
    [InlineData(false, 1, 0, false, false, false)]
    public void Passkey_keeps_one_method(
        bool password,
        int passkeys,
        int logins,
        bool emailCodeMapped,
        bool emailConfirmed,
        bool allowed)
    {
        Assert.Equal(allowed, CanRemove(password, passkeys, logins, emailCodeMapped, emailConfirmed, SignInMethod.Passkey));
    }

    [Fact]
    public void Password_and_email_code_are_not_removed_by_this_policy()
    {
        Assert.False(CanRemove(true, 1, 1, true, true, SignInMethod.Password));
        Assert.False(CanRemove(true, 1, 1, true, true, SignInMethod.EmailCode));
    }

    private static bool CanRemove(
        bool password,
        int passkeys,
        int logins,
        bool emailCodeMapped,
        bool emailConfirmed,
        SignInMethod removing)
    {
        return SignInMethodPolicy.CanRemove(
            new SignInMethodFacts(password, passkeys, logins, emailCodeMapped, emailConfirmed),
            removing);
    }
}
