namespace AuthEndpoints.Jwt;

internal class SimpleJwtErrorResponse
{
    public IEnumerable<string> Errors { get; set; }

    /// <summary>
    /// instantiate a new error response with the given error message
    /// </summary>
    /// <param name="errorMessage"></param>
    public SimpleJwtErrorResponse(string errorMessage)
    {
        Errors = new List<string>() { errorMessage };
    }

    /// <summary>
    /// instantiate a new error response with the given list of error messages
    /// </summary>
    /// <param name="errors"></param>
    public SimpleJwtErrorResponse(IEnumerable<string> errors)
    {
        Errors = errors;
    }
}
