# Tests

This directory contains the test suite for the TLScope project.

## Test Structure

- `test_cert.py` - Tests for certificate analysis functionality (`cert.py`)
- `test_tls.py` - Tests for TLS protocol analysis (`tls.py`)
- `test_cli.py` - Tests for CLI interface (`cli.py`)

## Running Tests

### Run all tests:
```bash
uv run pytest
```

### Run with verbose output:
```bash
uv run pytest -v
```

### Run specific test file:
```bash
uv run pytest tests/test_cert.py
```

### Run specific test:
```bash
uv run pytest tests/test_cert.py::TestCertAnalyzer::test_analyze_certificate_valid
```

### Run with coverage report:
```bash
uv run pytest --cov=src/tlscope --cov-report=term-missing
```

### Run with HTML coverage report:
```bash
uv run pytest --cov=src/tlscope --cov-report=html
# Then open htmlcov/index.html in a browser
```

## Test Coverage

The test suite currently provides ~90% code coverage of the main functionality:

- ✅ Certificate loading from files and URLs
- ✅ Certificate parsing (PEM and DER formats)
- ✅ Certificate validation and expiry checking
- ✅ Subject Alternative Names (SAN) extraction
- ✅ Certificate information extraction
- ✅ TLS protocol version detection
- ✅ Cipher suite enumeration
- ✅ CLI argument parsing and handling
- ✅ Error handling for various failure scenarios

## Test Fixtures

The test suite uses several fixtures to generate test certificates:

- `sample_cert` - A valid certificate for testing standard functionality
- `expired_cert` - An expired certificate for testing expiry detection
- `test_cert_path` - Path to the test certificate file in the tests directory

## Writing New Tests

When adding new functionality, please add corresponding tests:

1. Follow the existing test structure and naming conventions
2. Use descriptive test names that explain what is being tested
3. Include both positive and negative test cases
4. Mock external dependencies (network calls, file I/O when appropriate)
5. Aim to maintain or improve overall code coverage
