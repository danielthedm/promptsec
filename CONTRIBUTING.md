# Contributing to promptsec

Contributions are welcome! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/danielthedm/promptsec.git
cd promptsec
go test ./...
```

## Running Tests

```bash
go test ./...           # all tests
go test -race ./...     # with race detector
go test -bench=. ./...  # benchmarks
```

## Code Style

- Run `gofumpt` before committing
- Run `golangci-lint run` to check for issues
- Keep comments minimal and meaningful
- No external runtime dependencies (stdlib only, plus `golang.org/x/text`)

## Adding a New Guard

1. Create a new package under `guard/`
2. Implement the `Guard` interface from the root package
3. Add a `With*` functional option in `options.go`
4. Add tests
5. Update presets if appropriate

## Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure all tests pass
5. Submit a pull request

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
