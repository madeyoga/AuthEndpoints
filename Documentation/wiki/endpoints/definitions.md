### Implementing your own Endpoint Definition

You can define your own minimal api endpoint definition by implementing the `IEndpointDefintion` inerface.

```cs
internal class MyEndpointsDefinition : IEndpointDefinition
{
  public void MapEndpoints(WebApplication app) 
  {
    app.MapGet("/helloworld", HelloWorldEndpoint);
  }

  private Task<IResult> HelloWorldEndpoint()
  {
    return Task.FromResult(Results.Ok());
  }
}
```

Add your endpoint definition

```cs
var endpointsBuilder = builder.Services.AddAuthEndpointsCore<string, IdentityUser>();
endpointsBuilder.AddJwtEndpoints();

builder.Services.AddEndpointDefinition<MyEndpointDefinition>(); // <--

var app = builder.Build();

...

app.UseAuthentication();
app.UseAuthorization();

...

app.MapEndpoints(); // <--

app.Run();
```
