### Using IEndpointDefinition

You can define your own minimal api endpoint definition by implementing the `IEndpointDefintion` interface.

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
builder.Services.AddEndpointDefinition<MyEndpointDefinition>(); // <--

var app = builder.Build();

...

app.UseAuthentication();
app.UseAuthorization();

...

app.MapEndpoints(); // <--

app.Run();
```
