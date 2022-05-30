namespace AuthEndpoints;

/// <summary>
/// Represents all the options you can use to configure the Email backend
/// </summary>
public class EmailOptions
{
    public string From { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 587;
    public string User { get; set; } = "";
    public string Password { get; set; } = "";
}
