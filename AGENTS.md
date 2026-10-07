## Cursor Cloud specific instructions

The standalone Aspire dashboard (13.6.0) is installed by `.cursor/install.sh` under `/opt/aspire-dashboard/13.6.0` and started on boot by `.cursor/start-aspire-dashboard.sh` (`start` in `.cursor/environment.json`). It listens on localhost only. Logs are `/tmp/aspire-dashboard.log`. If the UI is not up, run `bash .cursor/start-aspire-dashboard.sh` (a second run does not start another instance).

- UI: http://localhost:18888
- OTLP/gRPC: http://localhost:4317
- OTLP/HTTP: http://localhost:4318

### Send traces from the demo API

The runnable host is `tests/AuthEndpoints.Tests` (`dotnet` on `AuthEndpoints.Tests.dll`, or `.cursor/skills/verify-authendpoints/scripts/ae-http.sh launch`). It exports traces only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. `ae-http.sh launch` sets these when they are unset, and passes them through to the process:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export OTEL_SERVICE_NAME=authendpoints-demo
```

`OTEL_SERVICE_NAME` is the resource name. The host adds ASP.NET Core, HttpClient, and EF Core instrumentation. The exporter batches spans (about every 5 seconds), so wait briefly before reading them. An empty `OTEL_EXPORTER_OTLP_ENDPOINT` leaves export off. `dotnet test` does not set these variables.

### Read traces

```bash
curl -s localhost:18888/api/telemetry/resources
curl -s localhost:18888/api/telemetry/traces
curl -s 'localhost:18888/api/telemetry/traces?resource=authendpoints-demo'
```

Repeat `resource` to include more than one resource (`?resource=authendpoints-demo&resource=other`). The response is `{ data, totalCount, returnedCount }` with OTLP spans in `data.resourceSpans`. ASP.NET Core span names match the route, such as `POST /identity/register`. Traces are evidence to cite in PR verification. Do not commit them.
