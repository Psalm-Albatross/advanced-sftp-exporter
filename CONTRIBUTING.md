# Contributing to advanced-sftp-exporter

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites
- Go 1.25.5 or later
- Git
- Make

### Local Development

```bash
# Clone the repository
git clone https://github.com/your-username/advanced-sftp-exporter.git
cd advanced-sftp-exporter

# Install dependencies
go mod download

# Run tests
make test

# Build locally
make build

# Check code quality
make lint
```

## Code Style

- Follow Go conventions and idioms
- Run `make fmt` before committing
- Keep functions small and focused
- Add comments for exported types and functions
- Write meaningful commit messages

## Testing

- Write tests for new features
- Ensure all tests pass: `make test`
- Aim for >80% code coverage
- Test edge cases and error conditions

## Commit Guidelines

```
<type>: <subject>

<body>

<footer>
```

### Types
- `feat` - New feature
- `fix` - Bug fix
- `perf` - Performance improvement
- `refactor` - Code refactoring
- `test` - Test additions/changes
- `docs` - Documentation changes
- `chore` - Build, CI, dependency updates

### Example
```
feat: add metrics export backend support

Implement pluggable metrics export backends with support for
Prometheus remote write and vector.dev endpoints. Includes
configuration validation and error handling.

Fixes #123
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make your changes and commit with proper messages
4. Add tests for new functionality
5. Run `make check` to verify quality
6. Push to your fork
7. Submit a pull request with a clear description

## Creating a New Phase

If implementing a new phase:

1. Create a new branch: `git checkout -b phase-X`
2. Implement the phase features
3. Create comprehensive tests
4. Update documentation
5. Build and validate the binary
6. Create a `PHASE-X-DELIVERY.md` file
7. Submit PR for review

## Reporting Issues

When reporting issues, include:
- OS and Go version
- Exporter version (run `./advanced-sftp-exporter -version`)
- Clear reproduction steps
- Expected vs actual behavior
- Relevant log output

## Questions?

- Check existing issues and discussions
- Review the README and documentation
- Look at similar code for patterns
- Post a question in the discussions forum

## Code of Conduct

Be respectful, inclusive, and professional in all interactions. We follow the Contributor Covenant Code of Conduct.

---

Thank you for contributing!
