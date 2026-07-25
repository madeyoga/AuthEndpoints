namespace AuthEndpoints.Identity;

public class AuthEndpointsConstants
{
    private const string Prefix = "AuthEndpoints";

    public const string ReAuthScheme = Prefix + ".ReAuth";
    public const string ReAuthBearerScheme = Prefix + ".ReAuth.Bearer";
    public const string ReAuthHeaderName = "X-AuthEndpoints-Reauth";

    public const string PasskeyObtainOptionsPolicy = Prefix + ".Passkey.ObtainOptions";
    public const string PasskeyRegisterPolicy = Prefix + ".Passkey.Register";
    public const string LoginPolicy = Prefix + ".Login";
    public const string AccountAbusePolicy = Prefix + ".AccountAbuse";
    public const string ConfirmIdentityPolicy = Prefix + ".ConfirmIdentity";
}
