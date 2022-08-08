using AuthEndpoints.Core;
using AuthEndpoints.Core.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Infrastructure;

public static class AuthEndpointsBuilderExtensions
{
    public static AuthEndpointsBuilder AddRefreshTokenStore<TContext>(this AuthEndpointsBuilder builder) where TContext : DbContext
    {
        builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository<TContext>>();
        return builder;
    }
}
