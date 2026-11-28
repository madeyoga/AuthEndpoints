using Microsoft.EntityFrameworkCore;

namespace AuthEndpoints.Identity;

/// <summary>
/// Treats a <see cref="DbUpdateException"/> from the EF Identity stores as a refused insert, and detaches the user
/// from the context the stores share, so a later <c>SaveChanges</c> does not insert it again.
/// </summary>
internal sealed class EntityFrameworkUserCreateFailureHandler<TUser, TContext>(TContext db) : IUserCreateFailureHandler<TUser>
    where TUser : class
    where TContext : DbContext
{
    public bool TryRecover(TUser user, Exception exception)
    {
        if (exception is not DbUpdateException)
        {
            return false;
        }

        var entry = db.Entry(user);
        if (entry.State != EntityState.Detached)
        {
            entry.State = EntityState.Detached;
        }

        return true;
    }
}
