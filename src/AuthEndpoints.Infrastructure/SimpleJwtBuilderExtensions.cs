using AuthEndpoints.SimpleJwt.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Infrastructure;

public static class SimpleJwtBuilderExtensions
{
    public static SimpleJwtBuilder AddRefreshTokenStore<TContext>(this SimpleJwtBuilder builder) where TContext : DbContext
    {
        builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository<TContext>>();
        return builder;
    }
}
