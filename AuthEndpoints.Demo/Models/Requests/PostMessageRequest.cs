namespace AuthEndpoints.Demo.Models.Requests;

using System.ComponentModel.DataAnnotations;

public class PostMessageRequest<T>
{
    [Required]
    public string? Content { get; set; }
    public T? Receiver { get; set; }
}
