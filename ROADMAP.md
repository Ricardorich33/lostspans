# Roadmap

## Next
- Read the OpenTelemetry Operator's `Instrumentation` resource (`spec.exporter.endpoint`, `spec.env` and per-language `env`), which injects `OTEL_` variables into pods
- Read `kubectl kustomize` directories directly, so overlays don't need a separate step
- A GitHub Actions example that renders a chart and runs lostspans on pull requests
- `--ignore RULE` for accepted findings

## Later
- SDK tests for Java, Python and Node.js in `tests/`, so rules that now cite Go's behavior can say what those SDKs do
- `OTEL_CONFIG_FILE` declarative config files
- Terraform and ECS task definitions as inputs
