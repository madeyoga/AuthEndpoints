using System.ComponentModel.DataAnnotations;

namespace AuthEndpoints.MinimalApi;

public class MinimalValidator : IMinimalValidator
{
    public ValidationResult Validate<T>(T model)
    {
        var result = new ValidationResult()
        {
            IsValid = true
        };

        var type = typeof(T);

        var properties = type.GetProperties();

        foreach(var property in properties)
        {
            var attributes = property.GetCustomAttributes(typeof(ValidationAttribute), true);

            foreach (var attribute in attributes)
            {
                var validationAttribute = attribute as ValidationAttribute;

                if (validationAttribute == null)
                {
                    continue;
                }

                var propertyValue = property.CanRead ? property.GetValue(model) : null;
                if (!validationAttribute.IsValid(propertyValue))
                {
                    result.Errors
                        .Add(validationAttribute.FormatErrorMessage(property.Name));
                    result.IsValid = false;
                }
            }
        }

        return result;
    }
}
