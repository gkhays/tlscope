# Contributing to TLScope

Thank you for your interest in contributing to TLScope! This document provides guidelines and instructions for contributing to the project.

## Getting Started

### Prerequisites

- Python 3.12 or higher
- [uv](https://github.com/astral-sh/uv) - A fast Python package installer and resolver

### Setting Up Your Development Environment

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/yourusername/tlscope.git
   cd tlscope
   ```

2. **Install dependencies:**
   ```bash
   uv sync
   ```

3. **Verify the installation:**
   ```bash
   uv run tlscope --help
   ```

## Development Workflow

### Making Changes

1. **Create a new branch** for your feature or bug fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** in the appropriate files under `src/tlscope/`

3. **Test your changes** locally:
   ```bash
   uv run tlscope --url https://example.com
   ```

### Running Tests

Run the test suite to ensure your changes don't break existing functionality:

```bash
uv run pytest
```

For testing with the included test server and client:

```bash
# In one terminal
cd tests
uv run python server.py

# In another terminal
cd tests
uv run python client.py
```

## Code Quality

### Linting and Formatting

This project uses [Ruff](https://docs.astral.sh/ruff/) for both linting and formatting. Ruff is a fast Python linter and formatter that replaces multiple tools like Flake8, Black, isort, and more.

#### Check for linting issues:
```bash
uvx ruff check
```

#### Automatically fix linting issues:
```bash
uvx ruff check --fix
```

#### Format code:
```bash
uvx ruff format
```

#### Run both linting and formatting:
```bash
uvx ruff check --fix
uvx ruff format
```

**Important:** Please ensure your code passes all linting checks and is properly formatted before submitting a pull request.

### Code Style Guidelines

- Follow PEP 8 conventions (enforced by Ruff)
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and concise
- Add type hints where appropriate

## Submitting Changes

### Pull Request Process

1. **Ensure your code is clean:**
   - All tests pass
   - Code is linted and formatted with Ruff
   - No unnecessary debug statements or comments

2. **Commit your changes** with clear, descriptive messages:
   ```bash
   git add .
   git commit -m "Add feature: description of your changes"
   ```

3. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Open a Pull Request** on GitHub:
   - Provide a clear title and description
   - Reference any related issues
   - Describe what your changes do and why

5. **Respond to feedback** from maintainers and make any requested changes

### Pull Request Guidelines

- Keep PRs focused on a single feature or bug fix
- Update documentation if you're changing functionality
- Add tests for new features
- Ensure backward compatibility when possible
- Follow the existing code structure and patterns

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs. actual behavior
- Your environment (OS, Python version, etc.)
- Any relevant error messages or logs

### Feature Requests

For feature requests, please describe:

- The problem you're trying to solve
- Your proposed solution
- Any alternative solutions you've considered
- Whether you're willing to implement it yourself

## Project Structure

```
tlscope/
├── src/
│   └── tlscope/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cert.py      # Certificate handling
│       ├── cli.py       # Command-line interface
│       └── tls.py       # TLS connection logic
├── tests/               # Test files and certificates
├── pyproject.toml       # Project configuration
└── README.md
```

## Questions?

If you have questions about contributing, feel free to:

- Open an issue for discussion
- Reach out to the maintainers

Thank you for contributing to TLScope! 🎉
