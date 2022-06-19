namespace AuthEndpoints.MinimalApi;

public interface IMinimalValidator
{
    ValidationResult Validate<T>(T model);
}
