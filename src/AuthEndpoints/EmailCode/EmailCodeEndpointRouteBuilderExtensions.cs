using AuthEndpoints.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.EmailCode;

public static class EmailCodeEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps <c>POST /emailCode/send</c> and <c>POST /emailCode/verify</c>.
    /// Send uses <see cref="AuthEndpointsConstants.EmailCodeSendPolicy"/>.
    /// Verify uses <see cref="AuthEndpointsConstants.LoginPolicy"/>.
    /// Neither route requires antiforgery.
    /// </summary>
    public static IEndpointConventionBuilder MapEmailCodeEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        EnsureEmailCodesMapped(endpoints.ServiceProvider);

        var group = endpoints.MapGroup("");
        group.MapPost("/emailCode/send", EmailCodeEndpoints<TUser>.Send)
            .RequireRateLimiting(AuthEndpointsConstants.EmailCodeSendPolicy);
        group.MapPost("/emailCode/verify", EmailCodeEndpoints<TUser>.Verify)
            .RequireRateLimiting(AuthEndpointsConstants.LoginPolicy);
        return group;
    }

    private static void EnsureEmailCodesMapped(IServiceProvider services)
    {
        var check = services.GetService<IEmailCodeModelCheck>();
        if (check is null)
        {
            throw new InvalidOperationException(
                "AddEmailCodeEndpoints must be called before MapEmailCodeEndpoints.");
        }

        check.EnsureMapped();
    }
}

internal interface IEmailCodeModelCheck
{
    void EnsureMapped();
}

internal sealed class EmailCodeModelCheck<TContext> : IEmailCodeModelCheck
    where TContext : DbContext
{
    private readonly IServiceScopeFactory _scopeFactory;

    public EmailCodeModelCheck(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public void EnsureMapped()
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TContext>();
        if (db.Model.FindEntityType(typeof(EmailCodeEntry)) is null)
        {
            throw new NotSupportedException(
                "MapEmailCodeEndpoints requires modelBuilder.UseEmailCodes() when email-code sign-in is enabled.");
        }
    }
}
