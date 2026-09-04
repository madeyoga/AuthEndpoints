using AuthEndpoints.Passkey;
using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.Tests;

public class UserIdHelperTests
{
    [Fact]
    public void CreateUserIdString_StringKey_ReturnsGuidShapedId()
    {
        var userId = UserIdHelper.CreateUserIdString(typeof(IdentityUser));

        Assert.True(Guid.TryParse(userId, out _), $"Expected a Guid-shaped id, got '{userId}'.");
    }

    [Fact]
    public void CreateUserIdString_GuidKey_ReturnsGuidShapedId()
    {
        var userId = UserIdHelper.CreateUserIdString(typeof(IdentityUser<Guid>));

        Assert.True(Guid.TryParse(userId, out _), $"Expected a Guid-shaped id, got '{userId}'.");
    }

    [Fact]
    public void CreateUserIdString_LongKey_ThrowsNotSupported()
    {
        var ex = Assert.Throws<NotSupportedException>(
            () => UserIdHelper.CreateUserIdString(typeof(IdentityUser<long>)));

        Assert.Contains("string or Guid", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateUserIdString_StringKey_UsesRegisteredFactory()
    {
        var factory = new FixedPasskeyUserIdFactory("custom-string-key-id");

        var userId = UserIdHelper.CreateUserIdString(typeof(IdentityUser), factory);

        Assert.Equal("custom-string-key-id", userId);
    }

    [Fact]
    public void CreateUserIdString_GuidKey_UsesRegisteredFactory()
    {
        var expected = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        var factory = new FixedPasskeyUserIdFactory(expected.ToString());

        var userId = UserIdHelper.CreateUserIdString(typeof(IdentityUser<Guid>), factory);

        Assert.Equal(expected.ToString(), userId);
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
