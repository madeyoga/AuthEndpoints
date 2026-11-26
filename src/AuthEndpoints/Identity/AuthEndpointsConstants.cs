namespace AuthEndpoints.Identity;

public class AuthEndpointsConstants
{
    private const string Prefix = "AuthEndpoints";

    public const string ReAuthScheme = Prefix + ".ReAuth";
    public const string ReAuthBearerScheme = Prefix + ".ReAuth.Bearer";
    public const string ReAuthHeaderName = "X-AuthEndpoints-Reauth";

    /// <summary>
    /// The scheme name <c>AddAnyCallerScheme</c> registers by default: <c>AuthEndpoints.AnyCaller</c>. Use it in a policy,
    /// for example <c>AddAuthenticationSchemes(AuthEndpointsConstants.AnyCallerScheme)</c>.
    /// </summary>
    public const string AnyCallerScheme = Prefix + ".AnyCaller";

    public const string PasskeyObtainOptionsPolicy = Prefix + ".Passkey.ObtainOptions";
    public const string PasskeyRegisterPolicy = Prefix + ".Passkey.Register";
    public const string LoginPolicy = Prefix + ".Login";
    public const string EmailCodeSendPolicy = Prefix + ".EmailCode.Send";
    public const string AccountAbusePolicy = Prefix + ".AccountAbuse";
    public const string ConfirmIdentityPolicy = Prefix + ".ConfirmIdentity";
    public const string ConfirmIdentityEmailCodePolicy = Prefix + ".ConfirmIdentity.EmailCode";
}
