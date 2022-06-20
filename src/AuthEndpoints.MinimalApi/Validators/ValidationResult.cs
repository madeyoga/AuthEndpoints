namespace AuthEndpoints.MinimalApi;

public class ValidationResult
{
    public bool IsValid { get; set; }
    public IList<string> Errors { get; set; } = new List<string>();
}
