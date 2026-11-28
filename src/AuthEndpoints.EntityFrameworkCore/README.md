# AuthEndpoints.EntityFrameworkCore

EF Core storage for [AuthEndpoints](https://www.nuget.org/packages/AuthEndpoints). It registers the ASP.NET Core Identity EF stores and the AuthEndpoints stores for email codes, refresh tokens and active sessions, all in your `DbContext`.

```cs
builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlite("Data Source=app.db"));
builder.Services.AddAuthEndpoints<AppUser>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddPassword()
    .AddEmailCode();
```

Map the AuthEndpoints tables you use in `OnModelCreating`:

```cs
protected override void OnModelCreating(ModelBuilder builder)
{
    base.OnModelCreating(builder);
    builder.UseEmailCodes();        // email code
    builder.UseRefreshToken();      // JWT
    builder.UseActiveSessions();    // active sessions, after UseRefreshToken
}
```

To use other storage, skip this package and register your own `IUserStore<TUser>`, `IEmailCodeStore`, `IRefreshTokenStore` and `IActiveSessionStore`.

Docs: https://authendpoints.harten.id
