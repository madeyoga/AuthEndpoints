using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using AuthEndpoints.Identity;
using Framework = Microsoft.AspNetCore.Identity.Data;

namespace AuthEndpoints.Tests.PublicApi;

/// <summary>
/// 5.0 replaced the Microsoft.AspNetCore.Identity.Data bodies with library types (#476 item 5).
/// Each one must read and write the same JSON as the type it replaced: the same property names in the same order,
/// with the same required members. The one intended difference: <see cref="AccountInfoResponse.Email"/> may be null.
/// </summary>
public class IdentityApiContractTests
{
    public static TheoryData<Type, Type> Pairs => new()
    {
        { typeof(PasswordLoginRequest), typeof(Framework.LoginRequest) },
        { typeof(PasswordRegisterRequest), typeof(Framework.RegisterRequest) },
        { typeof(BearerRefreshRequest), typeof(Framework.RefreshRequest) },
        { typeof(ConfirmationEmailRequest), typeof(Framework.ResendConfirmationEmailRequest) },
        { typeof(PasswordRecoveryRequest), typeof(Framework.ForgotPasswordRequest) },
        { typeof(PasswordResetRequest), typeof(Framework.ResetPasswordRequest) },
        { typeof(AccountInfoRequest), typeof(Framework.InfoRequest) },
        { typeof(AccountInfoResponse), typeof(Framework.InfoResponse) },
        { typeof(TwoFactorSettingsRequest), typeof(Framework.TwoFactorRequest) },
        { typeof(TwoFactorSettingsResponse), typeof(Framework.TwoFactorResponse) },
    };

    [Theory]
    [MemberData(nameof(Pairs))]
    public void LibraryType_HasTheSameJsonShape_AsTheFrameworkType(Type library, Type framework)
    {
        var expected = Shape(framework);
        if (library == typeof(AccountInfoResponse))
        {
            // Identity allows an account without an email, so the library does not require one.
            expected = expected.Select(p => p.Name == "email" ? p with { Required = false } : p).ToList();
        }

        Assert.Equal(expected, Shape(library));
    }

    [Fact]
    public void AccountInfoResponse_WritesNullEmail()
    {
        var json = JsonSerializer.Serialize(new AccountInfoResponse { Email = null, IsEmailConfirmed = false }, Web);

        Assert.Equal("""{"email":null,"isEmailConfirmed":false}""", json);
    }

    [Fact]
    public void PasswordLoginRequest_MissingRequiredMember_FailsLikeTheFrameworkType()
    {
        const string body = """{"email":"a@test.local"}""";

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Framework.LoginRequest>(body, Web));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<PasswordLoginRequest>(body, Web));
    }

    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web)
    {
        TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
    };

    private sealed record Member(string Name, Type Type, bool Required);

    private static List<Member> Shape(Type type) => Web.GetTypeInfo(type).Properties
        .Select(property => new Member(property.Name, property.PropertyType, property.IsRequired))
        .ToList();
}
