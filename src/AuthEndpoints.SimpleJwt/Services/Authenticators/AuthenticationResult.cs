using Microsoft.AspNetCore.Identity;

namespace AuthEndpoints.SimpleJwt;

public class AuthenticationResult<TUser>
    where TUser : class
{
    private readonly List<AuthenticationError> _errors = new();

    /// <summary>
    /// Flag indicating whether if the operation succeeded or not.
    /// </summary>
    /// <value>True if the operation succeeded, otherwise false.</value>
    public bool Succeeded { get; protected set; }

    public IEnumerable<AuthenticationError> Errors => _errors;

    public TUser? User { get; protected set; }

    public static AuthenticationResult<TUser> Success(TUser user)
    {
        return new AuthenticationResult<TUser>() { Succeeded = true, User = user };
    }

    public static AuthenticationResult<TUser> Failed(params AuthenticationError[] errors)
    {
        var result = new AuthenticationResult<TUser> { Succeeded = false, User = null };
        if (errors != null)
        {
            result._errors.AddRange(errors);
        }
        return result;
    }
}
