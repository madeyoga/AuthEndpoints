# Endpoint Definitions

Currently endpoints are split into 3 EndpointDefinition classes:

- BasicAuthEndpointDefinition
- JwtEndpointDefinition
- TwoFactorEndpointDefinition

These definitions are automatically added when `.AddAllEndpointDefinitions()` is being used. 

### Manually add endpoint definition

Instead of adding all the definitions, You can also add each of them manually depending on your needs. For example, you only need basic auth and jwt endpoints:

```cs
builder.Services
  .AddAuthEndpoints<string, IdentityUser>()
  .AddBasicAuthenticationEndpoints() // <--
  .AddJwtEndpoints() // <--
  .AddJwtBearerAuthScheme();
```

### Extending endpoint definition

You can also customise these endpoint definitions to match your exact needs. For example in basic auth definition, you want to exclude the email verification endpoints. In this case, you can extend the `BasicAuthEndpointDefinition` and override the `MapEndpoints(WebApplication app)` method. Checkout [api reference](xref:AuthEndpoints.MinimalApi.BasicAuthEndpointDefinition`2) for more info.

```cs
internal class MyAuthEndpointDefinition : BasicAuthEndpointDefinition<string, IdentityUser>
{
  internal override void MapEndpoints(WebApplication app)
  {
    string baseUrl = "/users";
    app.MapPost($"{baseUrl}", Register);
    app.MapGet($"{baseUrl}/me", GetMe);
    app.MapPost($"{baseUrl}/set_password", SetPassword);
    app.MapPost($"{baseUrl}/reset_password", ResetPassword);
    app.MapPost($"{baseUrl}/reset_password_confirm", ResetPasswordConfirm);
    app.MapDelete($"{baseUrl}/delete", Delete);
  }
}
```

Then register it via `AddEndpointDefinition<>()`

```cs
builder.Services
  .AddAuthEndpoints<string, IdentityUser>()
  .AddEndpointDefinition<MyAuthEndpointDefinition>() // <-- Add your endpoint definition.
  .AddJwtEndpoints() // <--
  .AddJwtBearerAuthScheme();
```

### Implementing your own Endpoints Definition

You can define your own minimal api endpoint definition by implementing the `IEndpointDefintion` inerface.

```cs
internal class MyEndpointsDefinition : IEndpointDefinition
{
  internal void MapEndpoints(WebApplication app) 
  {
    app.MapGet("/helloworld", HelloWorldEndpoint);
  }

  internal Task<IResult> HelloWorldEndpoint()
  {
    return Task.FromResult(Results.Ok());
  }
}
```

Add your endpoint definition

```cs
var endpointsBuilder = builder.Services
  .AddAuthEndpoints<string, IdentityUser>();
  .AddEndpointDefinition<MyEndpointsDefinition>() // <-- Add your endpoint definition
  .AddJwtEndpoints(); // <--

endpointsBuilder.AddJwtBearerAuthScheme();
endpointsBuilder.AddEndpointDefinition<MyEndpointsDefinition>();
endpointsBuilder.AddJwtEndpoints();

var app = builder.Build();

...

app.UseAuthentication();
app.UseAuthorization();

...

app.MapAuthEndpoints(); // <--

app.Run();
```
