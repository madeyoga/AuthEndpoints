namespace AuthEndpoints;

public class EmailOptions
{
    public string? From { get; set; }
    public string? Host { get; set; }
    public int Port { get; set; } = 465;
    public string? User { get; set; }
    public string? Password { get; set; }
}
