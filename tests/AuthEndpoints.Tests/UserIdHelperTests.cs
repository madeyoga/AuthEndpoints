using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests;

public class UserIdHelperTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CreateUserIdString_StringOrGuidKey_ReturnsGuidShapedId(bool guidKey)
    {
        var userType = guidKey ? typeof(IdentityUser<Guid>) : typeof(IdentityUser);
        var userId = UserIdHelper.CreateUserIdString(userType);

        Assert.True(Guid.TryParse(userId, out _), $"Expected a Guid-shaped id, got '{userId}'.");
    }

    [Fact]
    public void CreateUserIdString_LongKey_ThrowsNotSupported()
    {
        var ex = Assert.Throws<NotSupportedException>(
            () => UserIdHelper.CreateUserIdString(typeof(IdentityUser<long>)));

        Assert.Contains("string or Guid", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false, "custom-string-key-id")]
    [InlineData(true, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")]
    public void CreateUserIdString_SupportedKey_UsesRegisteredFactory(bool guidKey, string expected)
    {
        var userType = guidKey ? typeof(IdentityUser<Guid>) : typeof(IdentityUser);
        var factory = new FixedPasskeyUserIdFactory(expected);

        var userId = UserIdHelper.CreateUserIdString(userType, factory);

        Assert.Equal(expected, userId);
    }

    [Fact]
    public void CreateUserIdString_LongKey_ThrowsEvenWhenFactoryIsRegistered()
    {
        var factory = new FixedPasskeyUserIdFactory("1");

        var ex = Assert.Throws<NotSupportedException>(
            () => UserIdHelper.CreateUserIdString(typeof(IdentityUser<long>), factory));

        Assert.Contains("string or Guid", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SetUserId_StringKey_AssignsId()
    {
        var user = new IdentityUser();

        UserIdHelper.SetUserId(user, "string-user-id");

        Assert.Equal("string-user-id", user.Id);
    }

    [Fact]
    public void SetUserId_GuidKey_AssignsId()
    {
        var user = new IdentityUser<Guid>();
        var id = Guid.Parse("11111111-2222-3333-4444-555555555555");

        UserIdHelper.SetUserId(user, id.ToString());

        Assert.Equal(id, user.Id);
    }

    private sealed class FixedPasskeyUserIdFactory(string userId) : IPasskeyUserIdFactory
    {
        public string CreateUserId() => userId;
    }
}
