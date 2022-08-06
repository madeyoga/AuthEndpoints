namespace AuthEndpoints.Models;

/// <summary>
/// The dto used to send an error response to the client
/// </summary>
public class ErrorResponse
{
    public IEnumerable<string> Errors { get; set; }

    /// <summary>
    /// instantiate a new error response with the given error message
    /// </summary>
    /// <param name="errorMessage"></param>
    public ErrorResponse(string errorMessage)
    {
        Errors = new List<string>() { errorMessage };
    }

    /// <summary>
    /// instantiate a new error response with the given list of error messages
    /// </summary>
    /// <param name="errors"></param>
    public ErrorResponse(IEnumerable<string> errors)
    {
        Errors = errors;
    }
}