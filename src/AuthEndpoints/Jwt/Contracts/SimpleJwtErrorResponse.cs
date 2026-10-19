namespace AuthEndpoints.Jwt;

internal class SimpleJwtErrorResponse
{
    public IEnumerable<string> Errors { get; set; }

    public SimpleJwtErrorResponse(string errorMessage)
    {
        Errors = new List<string>() { errorMessage };
    }

    public SimpleJwtErrorResponse(IEnumerable<string> errors)
    {
        Errors = errors;
    }
}
