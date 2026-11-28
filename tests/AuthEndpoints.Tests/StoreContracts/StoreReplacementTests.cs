using AuthEndpoints.EmailCode;
using AuthEndpoints.Jwt;
using AuthEndpoints.Sessions;
using AuthEndpoints.Tests.Sessions;
using Microsoft.Extensions.DependencyInjection;

namespace AuthEndpoints.Tests.StoreContracts;

/// <summary>
/// The custom-stores guide: a store registered before <c>AddEntityFrameworkStores</c> replaces only that store.
/// </summary>
public sealed class StoreReplacementTests
{
    [Fact]
    public void A_store_registered_first_wins_and_the_ef_stores_fill_the_rest()
    {
        var emailCodes = new InMemoryEmailCodeStore();
        var services = new ServiceCollection();
        services.AddSingleton<IEmailCodeStore>(emailCodes);
        services.AddAuthEndpoints<TestAppUser>().AddEntityFrameworkStores<ActiveSessionsDbContext>();

        Assert.Same(emailCodes, Assert.Single(services, d => d.ServiceType == typeof(IEmailCodeStore)).ImplementationInstance);
        Assert.Single(services, d => d.ServiceType == typeof(IRefreshTokenStore));
        Assert.Single(services, d => d.ServiceType == typeof(IActiveSessionStore));
    }
}
