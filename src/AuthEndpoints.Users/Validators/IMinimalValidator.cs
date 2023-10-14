namespace AuthEndpoints.Users.Validators;

public interface IMinimalValidator
{
    ValidationResult Validate<T>(T model);
}
