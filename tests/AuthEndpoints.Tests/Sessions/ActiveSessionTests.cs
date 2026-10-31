using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AuthEndpoints.EmailCode;
using AuthEndpoints.Identity;
using AuthEndpoints.Jwt;
using AuthEndpoints.Sessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthEndpoints.Tests.Sessions;

public class ActiveSessionTests
{
    private const string Password = "Passw0rd!";

    [Fact]
    public async Task EachCookieSignIn_CreatesOneSession_AndListMarksCurrent()
    {
        await using var host = await CookieHost.StartAsync();
        var email = Email();
        await host.SeedAsync(email, Password);

        var byPassword = await host.SignInPasswordAsync(email, Password, userAgent: "phone-browser");
        var byCode = await host.SignInEmailCodeAsync(email);
        Assert.Equal(2, await host.CountSessionsAsync(email));

        var list = await host.ListAsync(byPassword);
        Assert.Equal(2, list.Count);
        var current = Assert.Single(list, s => s.Current);
        Assert.Equal("phone-browser", current.UserAgent);
        Assert.True(current.CreatedAt <= current.LastSeenAt);

        var other = await host.ListAsync(byCode);
        Assert.Single(other, s => s.Current);
        Assert.NotEqual(current.Id, Assert.Single(other, s => s.Current).Id);

        // Using the cookie again does not add records.
        await host.ListAsync(byPassword);
        Assert.Equal(2, await host.CountSessionsAsync(email));
    }

    [Fact]
    public async Task List_ShowsOnlyCallersSessions_AndRevokeOfForeignSessionIs404()
    {
        await using var host = await CookieHost.StartAsync();
        var mine = Email();
        var theirs = Email();
        await host.SeedAsync(mine, Password);
        await host.SeedAsync(theirs, Password);
        var me = await host.SignInPasswordAsync(mine, Password);
        var them = await host.SignInPasswordAsync(theirs, Password);
        var theirId = Assert.Single(await host.ListAsync(them)).Id;

        var myList = await host.ListAsync(me);
        Assert.DoesNotContain(myList, s => s.Id == theirId);

        await host.ConfirmPasswordAsync(me, Password);
        Assert.Equal(HttpStatusCode.NotFound, (await host.SendAsync(me, HttpMethod.Delete, $"/identity/sessions/{theirId}", csrf: true)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await host.SendAsync(me, HttpMethod.Delete, "/identity/sessions/missing", csrf: true)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync(them, "/identity/manage/info")).StatusCode);
    }

    [Fact]
    public async Task Revoke_RequiresReauthAndCsrf_ThenOtherCookieGets401()
    {
        await using var host = await CookieHost.StartAsync();
        var email = Email();
        await host.SeedAsync(email, Password);
        var actor = await host.SignInPasswordAsync(email, Password);
        var victim = await host.SignInPasswordAsync(email, Password);
        var victimId = Assert.Single(await host.ListAsync(victim), s => s.Current).Id;

        Assert.Equal(HttpStatusCode.Forbidden, (await host.SendAsync(actor, HttpMethod.Delete, $"/identity/sessions/{victimId}", csrf: true)).StatusCode);
        await host.ConfirmPasswordAsync(actor, Password);
        Assert.Equal(HttpStatusCode.BadRequest, (await host.SendAsync(actor, HttpMethod.Delete, $"/identity/sessions/{victimId}", csrf: false)).StatusCode);

        var revoked = await host.SendAsync(actor, HttpMethod.Delete, $"/identity/sessions/{victimId}", csrf: true);
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetAsync(victim, "/identity/manage/info")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync(actor, "/identity/manage/info")).StatusCode);
        Assert.DoesNotContain(await host.ListAsync(actor), s => s.Id == victimId);
    }

    [Fact]
    public async Task RevokeOthers_KeepsCurrentSessionWorking()
    {
        await using var host = await CookieHost.StartAsync();
        var email = Email();
        await host.SeedAsync(email, Password);
        var actor = await host.SignInPasswordAsync(email, Password);
        var other1 = await host.SignInPasswordAsync(email, Password);
        var other2 = await host.SignInEmailCodeAsync(email);

        Assert.Equal(HttpStatusCode.Forbidden, (await host.SendAsync(actor, HttpMethod.Post, "/identity/sessions/revokeOthers", csrf: true)).StatusCode);
        await host.ConfirmPasswordAsync(actor, Password);
        var response = await host.SendAsync(actor, HttpMethod.Post, "/identity/sessions/revokeOthers", csrf: true);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, (await response.Content.ReadFromJsonAsync<RevokeOtherSessionsResponse>())!.Revoked);

        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync(actor, "/identity/manage/info")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetAsync(other1, "/identity/manage/info")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetAsync(other2, "/identity/manage/info")).StatusCode);
        Assert.True(Assert.Single(await host.ListAsync(actor)).Current);
    }

    [Fact]
    public async Task Logout_EndsSession()
    {
        await using var host = await CookieHost.StartAsync();
        var email = Email();
        await host.SeedAsync(email, Password);
        var keep = await host.SignInPasswordAsync(email, Password);
        var leaving = await host.SignInPasswordAsync(email, Password);

        var logout = await host.SendAsync(leaving, HttpMethod.Post, "/identity/logout", csrf: true);
        Assert.True(logout.IsSuccessStatusCode, logout.StatusCode.ToString());

        Assert.Single(await host.ListAsync(keep));
        Assert.Equal(1, await host.CountActiveAsync(email));
    }

    [Fact]
    public async Task PasswordSet_EndsOtherSessions_AndKeepsCurrent()
    {
        await using var host = await CookieHost.StartAsync();
        var email = Email();
        await host.SeedAsync(email, password: null);
        var actor = await host.SignInEmailCodeAsync(email);
        var other = await host.SignInEmailCodeAsync(email);
        var actorId = Assert.Single(await host.ListAsync(actor), s => s.Current).Id;

        await host.ConfirmEmailCodeAsync(actor, email);
        var set = await host.SendAsync(actor, HttpMethod.Post, "/identity/manage/password", csrf: true, new { newPassword = "SetPass1!" });
        Assert.Equal(HttpStatusCode.OK, set.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetAsync(other, "/identity/manage/info")).StatusCode);
        var remaining = Assert.Single(await host.ListAsync(actor));
        Assert.Equal(actorId, remaining.Id);
        Assert.True(remaining.Current);
        Assert.Equal(1, await host.CountActiveAsync(email));
    }

    [Fact]
    public async Task SecurityStampChange_EndsSessions()
    {
        await using var host = await CookieHost.StartAsync();
        var email = Email();
        await host.SeedAsync(email, Password);
        var jar = await host.SignInPasswordAsync(email, Password);
        Assert.Equal(1, await host.CountActiveAsync(email));

        using (var scope = host.App.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = await users.FindByEmailAsync(email);
            await users.UpdateSecurityStampAsync(user!);
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetAsync(jar, "/identity/manage/info")).StatusCode);
        Assert.Equal(0, await host.CountActiveAsync(email));
    }

    [Fact]
    public async Task Cleanup_DeletesRevokedAndExpiredSessions()
    {
        await using var host = await CookieHost.StartAsync();
        var email = Email();
        await host.SeedAsync(email, Password);
        var keep = await host.SignInPasswordAsync(email, Password);
        var revoked = await host.SignInPasswordAsync(email, Password);
        var expired = await host.SignInPasswordAsync(email, Password);
        var revokedId = Assert.Single(await host.ListAsync(revoked), s => s.Current).Id;
        var expiredId = Assert.Single(await host.ListAsync(expired), s => s.Current).Id;
        await host.SendAsync(revoked, HttpMethod.Post, "/identity/logout", csrf: true);

        using (var scope = host.App.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ActiveSessionsDbContext>();
            await db.Set<ActiveSession>().Where(s => s.Id == expiredId)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, DateTime.UtcNow.AddMinutes(-1)));
        }

        Assert.Equal(2, await ActiveSessionHostedService<ActiveSessionsDbContext>.CleanupOnceAsync(host.App.Services));

        using (var scope = host.App.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ActiveSessionsDbContext>();
            var ids = await db.Set<ActiveSession>().Select(s => s.Id).ToListAsync();
            Assert.Single(ids);
            Assert.DoesNotContain(revokedId, ids);
            Assert.DoesNotContain(expiredId, ids);
        }

        Assert.Equal(HttpStatusCode.OK, (await host.GetAsync(keep, "/identity/manage/info")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetAsync(expired, "/identity/manage/info")).StatusCode);
    }

    [Fact]
    public async Task LastSeen_IsThrottled()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ae-sessions-touch-{Guid.NewGuid():N}.sqlite");
        try
        {
            var options = new DbContextOptionsBuilder<ActiveSessionsDbContext>().UseSqlite($"Data Source={path}").Options;
            await using var db = new ActiveSessionsDbContext(options);
            await db.Database.EnsureCreatedAsync();
            var time = new ManualTime(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
            var store = new ActiveSessionStore<ActiveSessionsDbContext>(
                db,
                time,
                Options.Create(new ActiveSessionOptions { LastSeenUpdateInterval = TimeSpan.FromMinutes(5) }));

            await store.CreateAsync("s1", "u1", "ua", "stamp", time.GetUtcNow().UtcDateTime.AddDays(1));
            var start = (await store.FindAsync("s1"))!.LastSeenAt;

            time.Advance(TimeSpan.FromMinutes(1));
            await store.TouchAsync((await store.FindAsync("s1"))!, null);
            Assert.Equal(start, (await store.FindAsync("s1"))!.LastSeenAt);

            time.Advance(TimeSpan.FromMinutes(5));
            await store.TouchAsync((await store.FindAsync("s1"))!, null);
            Assert.Equal(time.GetUtcNow().UtcDateTime, ActiveSessionStore.AsUtc((await store.FindAsync("s1"))!.LastSeenAt));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Jwt_SessionFollowsRefreshFamily_RevokeMakesRefreshFail()
    {
        await using var host = await JwtHost.StartAsync();
        var email = Email();
        await host.SeedAsync(email);

        var (access, refresh) = await host.CreateAsync(email);
        var list = await host.ListAsync(access);
        var session = Assert.Single(list);
        Assert.True(session.Current);

        var (access2, refresh2) = await host.RefreshAsync(refresh);
        var afterRefresh = Assert.Single(await host.ListAsync(access2));
        Assert.Equal(session.Id, afterRefresh.Id);
        Assert.True(afterRefresh.Current);

        var (otherAccess, otherRefresh) = await host.CreateAsync(email);
        Assert.Equal(2, (await host.ListAsync(otherAccess)).Count);

        using (var scope = host.App.Services.CreateScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<IActiveSessionStore>();
            var userId = (await scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>().FindByEmailAsync(email))!.Id;
            Assert.True(await store.RevokeAsync(userId, session.Id));
        }

        var failed = await host.Client.PostAsJsonAsync("/auth/refresh", new { refreshToken = refresh2 });
        Assert.False(failed.IsSuccessStatusCode);

        // The other device keeps refreshing.
        var (_, otherRefresh2) = await host.RefreshAsync(otherRefresh);

        var logout = await host.Client.PostAsJsonAsync("/auth/logout", new { refreshToken = otherRefresh2 });
        Assert.True(logout.IsSuccessStatusCode);
        Assert.Equal(0, await host.CountActiveAsync(email));
    }

    [Fact]
    public async Task Jwt_RevokeOthersEndpoint_KeepsCurrentFamily()
    {
        await using var host = await JwtHost.StartAsync();
        var email = Email();
        await host.SeedAsync(email);
        var (access, refresh) = await host.CreateAsync(email);
        var (_, otherRefresh) = await host.CreateAsync(email);

        using (var scope = host.App.Services.CreateScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<IActiveSessionStore>();
            var current = Assert.Single(await host.ListAsync(access), s => s.Current).Id;
            var userId = (await scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>().FindByEmailAsync(email))!.Id;
            Assert.Equal(1, await store.RevokeOthersAsync(userId, current));
        }

        Assert.False((await host.Client.PostAsJsonAsync("/auth/refresh", new { refreshToken = otherRefresh })).IsSuccessStatusCode);
        await host.RefreshAsync(refresh);
    }

    [Fact]
    public async Task IdentityBearerMapping_FailsStartup()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => CookieHost.StartAsync(mapIdentityBearer: true));
        Assert.Contains("cookie and JWT sign-in only", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingModel_FailsStartup()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseTestServer();
        builder.Services.AddDbContext<TestDbContext>(o => o.UseInMemoryDatabase($"sessions-missing-{Guid.NewGuid():N}"));
        builder.Services.AddIdentityApiEndpoints<TestAppUser>().AddEntityFrameworkStores<TestDbContext>();
        builder.Services.AddActiveSessions<TestAppUser, TestDbContext>();
        await using var app = builder.Build();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => app.StartAsync());
        Assert.Contains("UseActiveSessions", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void WithoutOptIn_ModelHasNoSessionTableOrColumn()
    {
        var options = new DbContextOptionsBuilder<TestDbContext>().UseSqlite("Data Source=:memory:").Options;
        using var db = new TestDbContext(options);
        Assert.Null(db.Model.FindEntityType(typeof(ActiveSession)));
        Assert.Null(db.Model.FindEntityType(typeof(RefreshToken))!.FindProperty(ActiveSessionModelBuilderExtensions.RefreshTokenSessionIdProperty));

        var optIn = new DbContextOptionsBuilder<ActiveSessionsDbContext>().UseSqlite("Data Source=:memory:").Options;
        using var sessions = new ActiveSessionsDbContext(optIn);
        Assert.NotNull(sessions.Model.FindEntityType(typeof(ActiveSession)));
        Assert.NotNull(sessions.Model.FindEntityType(typeof(RefreshToken))!.FindProperty(ActiveSessionModelBuilderExtensions.RefreshTokenSessionIdProperty));
    }

    [Fact]
    public void MapWithoutOptIn_Throws()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddRouting();
        var app = builder.Build();
        var error = Assert.Throws<InvalidOperationException>(() => app.MapActiveSessionEndpoints<TestAppUser>());
        Assert.Contains("AddActiveSessions", error.Message, StringComparison.Ordinal);
    }

    private static string Email() => $"sessions-{Guid.NewGuid():N}@test.local";

    private sealed class ManualTime(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    private abstract class HostBase : IAsyncDisposable
    {
        private readonly string _path;

        protected HostBase(WebApplication app, string path)
        {
            App = app;
            _path = path;
            Client = app.GetTestClient();
        }

        public WebApplication App { get; }

        public HttpClient Client { get; }

        protected static string NewPath(string name) => Path.Combine(Path.GetTempPath(), $"ae-sessions-{name}-{Guid.NewGuid():N}.sqlite");

        protected static async Task CreateDatabaseAsync(WebApplication app)
        {
            using var scope = app.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ActiveSessionsDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();
        }

        public async Task SeedAsync(string email, string? password = "Passw0rd!")
        {
            using var scope = App.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>();
            var user = new TestAppUser { UserName = email, Email = email, EmailConfirmed = true };
            var created = password is null ? await users.CreateAsync(user) : await users.CreateAsync(user, password);
            Assert.True(created.Succeeded, string.Join("; ", created.Errors.Select(e => e.Description)));
        }

        public async Task<int> CountActiveAsync(string email)
        {
            using var scope = App.Services.CreateScope();
            var user = await scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>().FindByEmailAsync(email);
            var db = scope.ServiceProvider.GetRequiredService<ActiveSessionsDbContext>();
            var now = DateTime.UtcNow;
            return await db.Set<ActiveSession>().CountAsync(s => s.UserId == user!.Id && s.RevokedAt == null && s.ExpiresAt > now);
        }

        public async Task<int> CountSessionsAsync(string email)
        {
            using var scope = App.Services.CreateScope();
            var user = await scope.ServiceProvider.GetRequiredService<UserManager<TestAppUser>>().FindByEmailAsync(email);
            var db = scope.ServiceProvider.GetRequiredService<ActiveSessionsDbContext>();
            return await db.Set<ActiveSession>().CountAsync(s => s.UserId == user!.Id);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await App.StopAsync();
            await App.DisposeAsync();
            SqliteConnection.ClearAllPools();
            foreach (var file in new[] { _path, _path + "-wal", _path + "-shm" })
            {
                try
                {
                    File.Delete(file);
                }
                catch (IOException)
                {
                }
            }
        }
    }

    private sealed class CookieHost : HostBase
    {
        private CookieHost(WebApplication app, string path, CapturingEmailSender mail)
            : base(app, path)
        {
            Mail = mail;
        }

        public CapturingEmailSender Mail { get; }

        public static async Task<CookieHost> StartAsync(bool mapIdentityBearer = false)
        {
            var path = NewPath("cookie");
            var mail = new CapturingEmailSender();
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<ActiveSessionsDbContext>(o => o.UseSqlite($"Data Source={path};Default Timeout=30"));
            builder.Services.AddSingleton<IEmailSender<TestAppUser>>(mail);
            builder.Services.AddSingleton<IEmailCodeSender<TestAppUser>>(mail);
            builder.Services.AddSingleton<IAccountSecurityEmailSender<TestAppUser>>(mail);
            builder.Services
                .AddIdentityApiEndpoints<TestAppUser>(options =>
                {
                    options.SignIn.RequireConfirmedAccount = true;
                    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                    options.Password.RequireDigit = false;
                    options.Password.RequireLowercase = false;
                    options.Password.RequireUppercase = false;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequiredLength = 6;
                })
                .AddEntityFrameworkStores<ActiveSessionsDbContext>()
                .AddDefaultTokenProviders();
            builder.Services.Configure<SecurityStampValidatorOptions>(o => o.ValidationInterval = TimeSpan.Zero);
            builder.Services.AddAuthorization();
            builder.Services.AddAntiforgery();
            builder.Services.AddPasswordSignInEndpoints();
            builder.Services.AddCookieSessionEndpoints();
            builder.Services.AddBearerSessionEndpoints();
            builder.Services.AddAccountManagementEndpoints();
            builder.Services.AddEmailCodeEndpoints<TestAppUser, ActiveSessionsDbContext>(o =>
            {
                o.ResendCooldown = TimeSpan.Zero;
                o.SendsPerIpPerMinute = 100;
            });
            builder.Services.AddActiveSessions<TestAppUser, ActiveSessionsDbContext>();

            var app = builder.Build();
            await CreateDatabaseAsync(app);
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseRateLimiter();
            app.UseAntiforgery();

            var identity = app.MapGroup("/identity");
            identity.MapPasswordSignInEndpoints<TestAppUser>();
            identity.MapCookieSessionEndpoints<TestAppUser>();
            identity.MapAccountManagementEndpoints<TestAppUser>();
            identity.MapEmailCodeSendEndpoints<TestAppUser>();
            identity.MapEmailCodeSignInEndpoints<TestAppUser>(AuthEndpointsSession.Cookie);
            identity.MapActiveSessionEndpoints<TestAppUser>();
            if (mapIdentityBearer)
            {
                var mobile = app.MapGroup("/mobile");
                mobile.MapEmailCodeSignInEndpoints<TestAppUser>(AuthEndpointsSession.IdentityBearer);
                mobile.MapBearerSessionEndpoints<TestAppUser>();
            }

            try
            {
                await app.StartAsync();
            }
            catch
            {
                await app.DisposeAsync();
                SqliteConnection.ClearAllPools();
                File.Delete(path);
                throw;
            }

            return new CookieHost(app, path, mail);
        }

        public async Task<CookieJar> SignInPasswordAsync(string email, string password, string? userAgent = null)
        {
            var jar = new CookieJar();
            var response = await SendAsync(jar, HttpMethod.Post, "/identity/login", csrf: false, new { email, password }, userAgent);
            Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
            return jar;
        }

        public async Task<CookieJar> SignInEmailCodeAsync(string email)
        {
            var sent = await Client.PostAsJsonAsync("/identity/emailCode/send", new { email });
            Assert.Equal(HttpStatusCode.OK, sent.StatusCode);
            var code = Mail.Snapshot().Last(i => i.Email == email && i.Purpose == EmailCodePurpose.SignIn).Body;
            var jar = new CookieJar();
            var response = await SendAsync(jar, HttpMethod.Post, "/identity/emailCode/verify?useSessionCookies=true", csrf: false, new { email, code });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return jar;
        }

        public async Task ConfirmPasswordAsync(CookieJar jar, string password)
        {
            var confirmed = await SendAsync(jar, HttpMethod.Post, "/identity/confirmIdentity", csrf: true, new { password });
            Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        }

        public async Task ConfirmEmailCodeAsync(CookieJar jar, string email)
        {
            var sent = await SendAsync(jar, HttpMethod.Post, "/identity/confirmIdentity/emailCode/send", csrf: true, new { });
            Assert.Equal(HttpStatusCode.OK, sent.StatusCode);
            var code = Mail.Snapshot().Last(i => i.Email == email && i.Purpose == EmailCodePurpose.ReAuth).Body;
            var confirmed = await SendAsync(jar, HttpMethod.Post, "/identity/confirmIdentity", csrf: true, new { emailCode = code });
            Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        }

        public async Task<List<ActiveSessionInfo>> ListAsync(CookieJar jar)
        {
            var response = await GetAsync(jar, "/identity/sessions");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return (await response.Content.ReadFromJsonAsync<List<ActiveSessionInfo>>())!;
        }

        public Task<HttpResponseMessage> GetAsync(CookieJar jar, string url) =>
            SendAsync(jar, HttpMethod.Get, url, csrf: false);

        public async Task<HttpResponseMessage> SendAsync(
            CookieJar jar,
            HttpMethod method,
            string url,
            bool csrf,
            object? body = null,
            string? userAgent = null)
        {
            string? token = csrf ? await CsrfAsync(jar) : null;
            using var request = new HttpRequestMessage(method, url);
            if (body is not null)
            {
                request.Content = JsonContent.Create(body);
            }

            if (token is not null)
            {
                request.Headers.TryAddWithoutValidation("RequestVerificationToken", token);
            }

            if (userAgent is not null)
            {
                request.Headers.TryAddWithoutValidation("User-Agent", userAgent);
            }

            request.Headers.TryAddWithoutValidation("Origin", Client.BaseAddress!.GetLeftPart(UriPartial.Authority));
            jar.Apply(request, Client.BaseAddress!);
            var response = await Client.SendAsync(request);
            jar.Capture(response, Client.BaseAddress!);
            return response;
        }

        private async Task<string> CsrfAsync(CookieJar jar)
        {
            var response = await GetAsync(jar, "/identity/csrfToken");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return TestHelpers.TryGetString(doc.RootElement, "csrfToken", "CsrfToken")!;
        }
    }

    private sealed class JwtHost : HostBase
    {
        private JwtHost(WebApplication app, string path)
            : base(app, path)
        {
        }

        public static async Task<JwtHost> StartAsync()
        {
            var path = NewPath("jwt");
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<ActiveSessionsDbContext>(o => o.UseSqlite($"Data Source={path};Default Timeout=30"));
            builder.Services.AddSingleton<IEmailSender<TestAppUser>>(new CapturingEmailSender());
            builder.Services.AddPasswordAuth<TestAppUser, ActiveSessionsDbContext>(o =>
            {
                o.Session = AuthEndpointsSession.Jwt;
                o.Jwt = jwt =>
                {
                    jwt.SigningOptions.SymmetricKey = "TestOnly_AuthEndpoints_Jwt_SigningKey_32chars!";
                    jwt.RefreshTokenTransport = RefreshTokenTransport.Body;
                };
            });
            builder.Services.AddActiveSessions<TestAppUser, ActiveSessionsDbContext>();

            var app = builder.Build();
            await CreateDatabaseAsync(app);
            app.UseAuthEndpoints();
            app.MapPasswordAuth<TestAppUser>();
            app.MapGroup("/auth").MapActiveSessionEndpoints<TestAppUser>();
            await app.StartAsync();
            return new JwtHost(app, path);
        }

        public async Task<(string Access, string Refresh)> CreateAsync(string email)
        {
            var response = await Client.PostAsJsonAsync("/auth/create", new { email, password = "Passw0rd!" });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return await ReadTokensAsync(response);
        }

        public async Task<(string Access, string Refresh)> RefreshAsync(string refresh)
        {
            var response = await Client.PostAsJsonAsync("/auth/refresh", new { refreshToken = refresh });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return await ReadTokensAsync(response);
        }

        public async Task<List<ActiveSessionInfo>> ListAsync(string access)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/sessions");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
            var response = await Client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return (await response.Content.ReadFromJsonAsync<List<ActiveSessionInfo>>())!;
        }

        private static async Task<(string, string)> ReadTokensAsync(HttpResponseMessage response)
        {
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return (
                TestHelpers.TryGetString(doc.RootElement, "accessToken", "AccessToken")!,
                TestHelpers.TryGetString(doc.RootElement, "refreshToken", "RefreshToken")!);
        }
    }

    private sealed class CookieJar
    {
        private readonly CookieContainer _cookies = new();

        public void Capture(HttpResponseMessage response, Uri baseAddress)
        {
            if (response.Headers.TryGetValues("Set-Cookie", out var values))
            {
                foreach (var value in values)
                {
                    _cookies.SetCookies(baseAddress, value);
                }
            }
        }

        public void Apply(HttpRequestMessage request, Uri baseAddress)
        {
            var header = _cookies.GetCookieHeader(baseAddress);
            if (!string.IsNullOrEmpty(header))
            {
                request.Headers.TryAddWithoutValidation("Cookie", header);
            }
        }
    }
}
