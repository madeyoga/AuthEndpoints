using System.ComponentModel.DataAnnotations.Schema;

namespace AuthEndpoints.Models;

public class Token <TUser>
{
    public int Id { get; set; }
    public string? Key { get; set; }

    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public DateTime? Created { get; set; } = DateTime.Now;

    public TUser? User { get; set; }
}
