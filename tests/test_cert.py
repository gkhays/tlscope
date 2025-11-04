"""Tests for certificate analysis functionality."""
import os
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID
import pytest

from tls_analyzer.cert import CertAnalyzer


@pytest.fixture
def test_cert_path():
    """Get path to test certificate."""
    return Path(__file__).parent / "server.pem"


@pytest.fixture
def sample_cert():
    """Create a sample certificate for testing."""
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])
    
    # Create certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("test.example.com"),
            x509.DNSName("www.test.example.com"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), backend=default_backend())
    
    return cert


@pytest.fixture
def expired_cert():
    """Create an expired certificate for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=400)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
    ).sign(private_key, hashes.SHA256(), backend=default_backend())
    
    return cert


class TestCertAnalyzer:
    """Tests for CertAnalyzer class."""
    
    def test_init(self, sample_cert):
        """Test CertAnalyzer initialization."""
        analyzer = CertAnalyzer(sample_cert)
        assert analyzer.certificate == sample_cert
    
    def test_get_issuer(self, sample_cert):
        """Test getting certificate issuer."""
        analyzer = CertAnalyzer(sample_cert)
        issuer = analyzer.get_issuer()
        assert issuer is not None
        assert any(attr.value == "Test Org" for attr in issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME))
    
    def test_get_subject(self, sample_cert):
        """Test getting certificate subject."""
        analyzer = CertAnalyzer(sample_cert)
        subject = analyzer.get_subject()
        assert subject is not None
        assert any(attr.value == "test.example.com" for attr in subject.get_attributes_for_oid(NameOID.COMMON_NAME))
    
    def test_load_cert_from_file(self, test_cert_path):
        """Test loading certificate from file."""
        if not test_cert_path.exists():
            pytest.skip("Test certificate file not found")
        
        analyzer = CertAnalyzer(None)
        cert_data = analyzer.load_cert_from_file(str(test_cert_path))
        assert cert_data is not None
        assert b"BEGIN CERTIFICATE" in cert_data or len(cert_data) > 0
    
    def test_load_cert_from_nonexistent_file(self):
        """Test loading from non-existent file returns None."""
        analyzer = CertAnalyzer(None)
        cert_data = analyzer.load_cert_from_file("/nonexistent/path/cert.pem")
        assert cert_data is None
    
    def test_parse_certificate_pem(self, sample_cert):
        """Test parsing PEM certificate."""
        analyzer = CertAnalyzer(None)
        pem_data = sample_cert.public_bytes(serialization.Encoding.PEM)
        parsed_cert = analyzer.parse_certificate(pem_data)
        assert parsed_cert is not None
        assert isinstance(parsed_cert, x509.Certificate)
    
    def test_parse_certificate_der(self, sample_cert):
        """Test parsing DER certificate."""
        analyzer = CertAnalyzer(None)
        der_data = sample_cert.public_bytes(serialization.Encoding.DER)
        parsed_cert = analyzer.parse_certificate(der_data)
        assert parsed_cert is not None
        assert isinstance(parsed_cert, x509.Certificate)
    
    def test_parse_certificate_invalid(self):
        """Test parsing invalid certificate data."""
        analyzer = CertAnalyzer(None)
        parsed_cert = analyzer.parse_certificate(b"invalid certificate data")
        assert parsed_cert is None
    
    def test_get_san_list(self, sample_cert):
        """Test extracting Subject Alternative Names."""
        analyzer = CertAnalyzer(None)
        san_list = analyzer.get_san_list(sample_cert)
        assert len(san_list) >= 2
        assert "DNS:test.example.com" in san_list
        assert "DNS:www.test.example.com" in san_list
    
    def test_get_san_list_no_san(self):
        """Test getting SAN from certificate without SAN extension."""
        # Create cert without SAN
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "noSan.example.com"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256(), backend=default_backend())
        
        analyzer = CertAnalyzer(None)
        san_list = analyzer.get_san_list(cert)
        assert san_list == []
    
    def test_analyze_certificate_valid(self, sample_cert):
        """Test analyzing a valid certificate."""
        analyzer = CertAnalyzer(None)
        info = analyzer.analyze_certificate(sample_cert)
        
        assert info is not None
        assert info["is_valid"] is True
        assert info["has_expired"] is False
        assert info["days_until_expiry"] > 0
        assert info["subject"]["CN"] == "test.example.com"
        assert info["subject"]["O"] == "Test Org"
        assert info["subject"]["C"] == "US"
        assert info["issuer"]["CN"] == "test.example.com"
        assert len(info["san"]) >= 2
    
    def test_analyze_certificate_expired(self, expired_cert):
        """Test analyzing an expired certificate."""
        analyzer = CertAnalyzer(None)
        info = analyzer.analyze_certificate(expired_cert)
        
        assert info is not None
        assert info["is_valid"] is False
        assert info["has_expired"] is True
        assert info["days_until_expiry"] < 0
        assert info["subject"]["CN"] == "expired.example.com"
    
    def test_print_certificate_info(self, sample_cert, capsys):
        """Test printing certificate information."""
        analyzer = CertAnalyzer(None)
        info = analyzer.analyze_certificate(sample_cert)
        analyzer.print_certificate_info(info, verbose=False)
        
        captured = capsys.readouterr()
        assert "TLS/SSL CERTIFICATE ANALYSIS" in captured.out
        assert "BASIC INFORMATION" in captured.out
        assert "SUBJECT" in captured.out
        assert "ISSUER" in captured.out
        assert "VALIDITY" in captured.out
        assert "test.example.com" in captured.out
    
    def test_print_certificate_info_verbose(self, sample_cert, capsys):
        """Test printing verbose certificate information."""
        analyzer = CertAnalyzer(None)
        info = analyzer.analyze_certificate(sample_cert)
        analyzer.print_certificate_info(info, verbose=True)
        
        captured = capsys.readouterr()
        assert "TLS/SSL CERTIFICATE ANALYSIS" in captured.out
        assert len(captured.out) > 100  # Should have substantial output
    
    def test_get_cert_from_url_invalid_host(self):
        """Test connecting to invalid host returns None."""
        analyzer = CertAnalyzer(None)
        result = analyzer.get_cert_from_url("invalid.nonexistent.host.example", 443, 2)
        assert result is None
    
    def test_serial_number_format(self, sample_cert):
        """Test serial number is formatted as hex."""
        analyzer = CertAnalyzer(None)
        info = analyzer.analyze_certificate(sample_cert)
        
        assert info["serial_number"] is not None
        # Should be hex string (only 0-9, A-F characters)
        assert all(c in "0123456789ABCDEF" for c in info["serial_number"])
    
    def test_certificate_version(self, sample_cert):
        """Test certificate version extraction."""
        analyzer = CertAnalyzer(None)
        info = analyzer.analyze_certificate(sample_cert)
        
        # Modern certificates are v3 (value 3)
        assert info["version"] == 3
