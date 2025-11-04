# TLScope

![Python](https://img.shields.io/badge/python-3.12+-blue.svg)

A Python tool for analyzing TLS/SSL certificates and connections.

## Quickstart

### Prerequisites
- Python 3.8+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Installation

With uv (recommended):
```bash
uv sync
```

With pip:
```bash
pip install -e .
```

### Usage

Analyze a TLS certificate for any URL:

```bash
uv run -m tlscope --url https://github.com
```

Or if installed with pip:
```bash
python -m tlscope --url https://github.com
```

The tool will display:
- Certificate subject and issuer information
- Validity period (not before/not after dates)
- TLS version and cipher suite
- Certificate chain details

### Example Output

```
Analyzing TLS connection to: github.com:443
TLS Version: TLSv1.3
Cipher: TLS_AES_128_GCM_SHA256
Certificate Details:
  Subject: CN=github.com
  Issuer: CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1
  Valid From: 2024-02-14
  Valid Until: 2025-02-14
```

## References
- [ssl — TLS/SSL wrapper for socket objects](https://docs.python.org/3/library/ssl.html)
