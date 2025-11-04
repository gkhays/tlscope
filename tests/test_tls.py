"""Tests for TLS analysis functionality."""
import ssl
from unittest.mock import Mock, MagicMock
import pytest

from tlscope.tls import TLSAnalyzer


class TestTLSAnalyzer:
    """Tests for TLSAnalyzer class."""
    
    def test_init_with_ssl_socket(self):
        """Test initialization with SSLSocket."""
        mock_socket = Mock(spec=ssl.SSLSocket)
        analyzer = TLSAnalyzer(mock_socket)
        assert analyzer.ssl_obj == mock_socket
    
    def test_init_with_ssl_context(self):
        """Test initialization with SSLContext."""
        context = ssl.create_default_context()
        analyzer = TLSAnalyzer(context)
        assert analyzer.ssl_obj == context
    
    def test_get_protocol_from_socket(self):
        """Test getting protocol version from SSLSocket."""
        mock_socket = Mock(spec=ssl.SSLSocket)
        mock_socket.version.return_value = "TLSv1.3"
        
        analyzer = TLSAnalyzer(mock_socket)
        protocol = analyzer.get_protocol()
        
        assert protocol == "TLSv1.3"
        mock_socket.version.assert_called_once()
    
    def test_get_protocol_from_socket_unknown(self):
        """Test getting protocol when socket returns None."""
        mock_socket = Mock(spec=ssl.SSLSocket)
        mock_socket.version.return_value = None
        
        analyzer = TLSAnalyzer(mock_socket)
        protocol = analyzer.get_protocol()
        
        assert protocol == "Unknown"
    
    def test_get_protocol_from_context_tls12(self):
        """Test getting protocol version from SSLContext with TLS 1.2."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        analyzer = TLSAnalyzer(context)
        protocol = analyzer.get_protocol()
        
        assert protocol == "TLSv1.2+"
    
    def test_get_protocol_from_context_tls13(self):
        """Test getting protocol version from SSLContext with TLS 1.3."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        
        analyzer = TLSAnalyzer(context)
        protocol = analyzer.get_protocol()
        
        assert protocol == "TLSv1.3+"
    
    def test_get_protocol_from_context_default(self):
        """Test getting protocol version from default SSLContext."""
        context = ssl.create_default_context()
        
        analyzer = TLSAnalyzer(context)
        protocol = analyzer.get_protocol()
        
        # Should return some TLS version string
        assert "TLS" in protocol
    
    def test_get_protocol_invalid_object(self):
        """Test getting protocol from invalid object."""
        invalid_obj = "not an ssl object"
        
        analyzer = TLSAnalyzer(invalid_obj)
        protocol = analyzer.get_protocol()
        
        assert protocol == "Unknown"
    
    def test_get_enabled_cipher_suites_from_socket(self):
        """Test getting cipher suites from SSLSocket."""
        mock_socket = Mock(spec=ssl.SSLSocket)
        mock_socket.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
        
        analyzer = TLSAnalyzer(mock_socket)
        ciphers = analyzer.get_enabled_cipher_suites()
        
        assert len(ciphers) == 1
        assert ciphers[0] == "ECDHE-RSA-AES256-GCM-SHA384"
        mock_socket.cipher.assert_called_once()
    
    def test_get_enabled_cipher_suites_from_socket_none(self):
        """Test getting cipher suites when socket returns None."""
        mock_socket = Mock(spec=ssl.SSLSocket)
        mock_socket.cipher.return_value = None
        
        analyzer = TLSAnalyzer(mock_socket)
        ciphers = analyzer.get_enabled_cipher_suites()
        
        assert ciphers == []
    
    def test_get_enabled_cipher_suites_from_context(self):
        """Test getting cipher suites from SSLContext."""
        context = ssl.create_default_context()
        
        analyzer = TLSAnalyzer(context)
        ciphers = analyzer.get_enabled_cipher_suites()
        
        # Should return a list of cipher suites
        assert isinstance(ciphers, list)
        assert len(ciphers) > 0
        # Each cipher should be a string
        assert all(isinstance(cipher, str) for cipher in ciphers)
    
    def test_get_enabled_cipher_suites_invalid_object(self):
        """Test getting cipher suites from invalid object."""
        invalid_obj = "not an ssl object"
        
        analyzer = TLSAnalyzer(invalid_obj)
        ciphers = analyzer.get_enabled_cipher_suites()
        
        assert ciphers == []
