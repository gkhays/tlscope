import ssl
import sys
import socket
import datetime
from typing import Dict, List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class CertAnalyzer:
    def __init__(self, certificate):
        self.certificate = certificate

    def get_issuer(self):
        return self.certificate.issuer

    def get_subject(self):
        return self.certificate.subject

    def get_cert_from_url(
        self, hostname: str, port: int = 443, timeout: int = 10
    ) -> Optional[Tuple[bytes, str]]:
        """Retrieve certificate from a remote server.

        Args:
            hostname: The hostname to connect to
            port: The port number (default: 443)
            timeout: Connection timeout in seconds (default: 10)

        Returns:
            Tuple of (Certificate in PEM format, TLS version) or None if failed
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    der_cert = secure_sock.getpeercert(binary_form=True)
                    tls_version = secure_sock.version()
                    return (ssl.DER_cert_to_PEM_cert(der_cert).encode(), tls_version)
        except Exception as e:
            print(f"Error connecting to {hostname}:{port}: {e}", file=sys.stderr)
            return None

    def load_cert_from_file(self, filepath: str) -> Optional[bytes]:
        """Load certificate from a local file.

        Args:
            filepath: Path to the certificate file

        Returns:
            Certificate data or None if failed
        """
        try:
            with open(filepath, "rb") as f:
                return f.read()
        except Exception as e:
            print(f"Error reading file {filepath}: {e}", file=sys.stderr)
            return None

    def parse_certificate(self, cert_data: bytes) -> Optional[x509.Certificate]:
        """Parse certificate data into X509 object.

        Args:
            cert_data: Certificate in PEM or DER format

        Returns:
            X509 certificate object or None if failed
        """
        try:
            return x509.load_pem_x509_certificate(cert_data, default_backend())
        except Exception:
            try:
                return x509.load_der_x509_certificate(cert_data, default_backend())
            except Exception as e:
                print(f"Error parsing certificate: {e}", file=sys.stderr)
                return None

    def get_san_list(self, cert: x509.Certificate) -> List[str]:
        """Extract Subject Alternative Names from certificate.

        Args:
            cert: X509 certificate object

        Returns:
            List of SAN entries
        """
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_list = [
                f"DNS:{name}"
                for name in san_ext.value.get_values_for_type(x509.DNSName)
            ]
            san_list.extend(
                [
                    f"IP:{str(ip)}"
                    for ip in san_ext.value.get_values_for_type(x509.IPAddress)
                ]
            )
        except x509.ExtensionNotFound:
            pass
        return san_list

    def analyze_certificate(self, cert: x509.Certificate) -> Dict:
        """Analyze certificate and extract relevant information.

        Args:
            cert: X509 certificate object

        Returns:
            Dictionary containing certificate details
        """
        # Parse dates
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)

        # Check validity
        is_valid = not_before <= now <= not_after
        days_until_expiry = (not_after - now).days
        has_expired = now > not_after

        # Helper function to extract attribute from Name
        def get_name_attribute(name, oid):
            try:
                attrs = name.get_attributes_for_oid(oid)
                return attrs[0].value if attrs else None
            except Exception:
                return None

        # Extract subject information
        subject_dict = {
            "CN": get_name_attribute(cert.subject, x509.oid.NameOID.COMMON_NAME),
            "O": get_name_attribute(cert.subject, x509.oid.NameOID.ORGANIZATION_NAME),
            "OU": get_name_attribute(
                cert.subject, x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME
            ),
            "C": get_name_attribute(cert.subject, x509.oid.NameOID.COUNTRY_NAME),
        }

        # Extract issuer information
        issuer_dict = {
            "CN": get_name_attribute(cert.issuer, x509.oid.NameOID.COMMON_NAME),
            "O": get_name_attribute(cert.issuer, x509.oid.NameOID.ORGANIZATION_NAME),
            "C": get_name_attribute(cert.issuer, x509.oid.NameOID.COUNTRY_NAME),
        }

        return {
            "version": cert.version.value + 1,
            "serial_number": format(cert.serial_number, "X"),
            "subject": subject_dict,
            "issuer": issuer_dict,
            "not_before": not_before.replace(tzinfo=None),
            "not_after": not_after.replace(tzinfo=None),
            "is_valid": is_valid,
            "days_until_expiry": days_until_expiry,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "san": self.get_san_list(cert),
            "has_expired": has_expired,
            "tls_version": None,  # Will be set from connection if available
        }

    def print_certificate_info(self, info: Dict, verbose: bool = False):
        """Print formatted certificate information.

        Args:
            info: Certificate information dictionary
            verbose: Whether to print detailed information
        """
        print("\n" + "=" * 60)
        print("TLS/SSL CERTIFICATE ANALYSIS")
        print("=" * 60)

        print("\n📋 BASIC INFORMATION")
        print(f"  Version: X.509 v{info['version']}")
        print(f"  Serial Number: {info['serial_number']}")
        print(f"  Signature Algorithm: {info['signature_algorithm']}")
        if info.get("tls_version"):
            print(f"  TLS Protocol: {info['tls_version']}")

        print("\n🔐 SUBJECT")
        for key, value in info["subject"].items():
            if value:
                print(f"  {key}: {value}")

        print("\n✍️  ISSUER")
        for key, value in info["issuer"].items():
            if value:
                print(f"  {key}: {value}")

        print("\n📅 VALIDITY")
        print(f"  Not Before: {info['not_before']}")
        print(f"  Not After:  {info['not_after']}")

        status_emoji = "✅" if info["is_valid"] and not info["has_expired"] else "❌"
        print(
            f"  Status: {status_emoji} {'Valid' if info['is_valid'] and not info['has_expired'] else 'Invalid/Expired'}"
        )

        if info["days_until_expiry"] > 0:
            print(f"  Days Until Expiry: {info['days_until_expiry']}")
        else:
            print(f"  Expired {abs(info['days_until_expiry'])} days ago")

        if info["san"]:
            print("\n🌐 SUBJECT ALTERNATIVE NAMES")
            for san in info["san"]:
                print(f"  - {san}")

        print("\n" + "=" * 60 + "\n")
