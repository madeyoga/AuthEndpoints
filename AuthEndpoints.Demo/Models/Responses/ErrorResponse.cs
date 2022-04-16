namespace AuthEndpoints.Demo.Models.Responses;

public class ErrorResponse
{
    public IEnumerable<string> Errors { get; set; }

    public ErrorResponse(string errorMessage)
    {
        Errors = new List<string>() { errorMessage };
    }

    public ErrorResponse(IEnumerable<string> errors)
    {
        Errors = errors;
    }
}
