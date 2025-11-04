import sys
import argparse
from urllib.parse import urlparse
from tlscope.cert import CertAnalyzer


def main():
    """Main entry point for the TLS analyzer."""
    parser = argparse.ArgumentParser(
        description="Analyze TLS/SSL certificates from URLs or files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://example.com
  %(prog)s --url example.com:443
  %(prog)s --file certificate.pem
  %(prog)s --url example.com --verbose
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--url",
        "-u",
        help="URL or hostname to analyze (e.g., https://example.com or example.com:443)",
    )
    group.add_argument(
        "--file", "-f", help="Path to certificate file (PEM or DER format)"
    )

    parser.add_argument(
        "--port", "-p", type=int, default=443, help="Port number (default: 443)"
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=int,
        default=10,
        help="Connection timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Display verbose output"
    )

    args = parser.parse_args()

    cert_data = None
    tls_version = None

    cert_analyzer = CertAnalyzer(certificate=None)  # Placeholder initialization

    if args.url:
        # Parse URL to extract hostname
        if not args.url.startswith(("http://", "https://")):
            hostname = args.url.split(":")[0]
            port = int(args.url.split(":")[1]) if ":" in args.url else args.port
        else:
            parsed = urlparse(args.url)
            hostname = parsed.hostname
            port = parsed.port or args.port

        print(f"Connecting to {hostname}:{port}...")
        result = cert_analyzer.get_cert_from_url(hostname, port, args.timeout)
        if result:
            cert_data, tls_version = result

    elif args.file:
        print(f"Loading certificate from {args.file}...")
        cert_data = cert_analyzer.load_cert_from_file(args.file)

    if not cert_data:
        print("Failed to retrieve certificate", file=sys.stderr)
        sys.exit(1)

    cert = cert_analyzer.parse_certificate(cert_data)
    if not cert:
        print("Failed to parse certificate", file=sys.stderr)
        sys.exit(1)

    info = cert_analyzer.analyze_certificate(cert)
    if tls_version:
        info["tls_version"] = tls_version
    cert_analyzer.print_certificate_info(info, args.verbose)

    # Exit with error code if certificate is invalid or expired
    if not info["is_valid"] or info["has_expired"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
