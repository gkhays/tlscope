"""Tests for CLI functionality."""
import sys
from unittest.mock import Mock, patch, MagicMock
import pytest

from tlscope.cli import main


class TestCLI:
    """Tests for CLI interface."""
    
    def test_main_no_arguments(self):
        """Test CLI with no arguments shows error."""
        with patch('sys.argv', ['tlscope']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2  # argparse error code
    
    def test_main_help_argument(self):
        """Test CLI with --help argument."""
        with patch('sys.argv', ['tlscope', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
    
    def test_main_url_argument(self, capsys):
        """Test CLI with --url argument."""
        with patch('sys.argv', ['tlscope', '--url', 'example.com']):
            with patch('tlscope.cert.CertAnalyzer.get_cert_from_url') as mock_get:
                with patch('tlscope.cert.CertAnalyzer.parse_certificate') as mock_parse:
                    with patch('tlscope.cert.CertAnalyzer.analyze_certificate') as mock_analyze:
                        with patch('tlscope.cert.CertAnalyzer.print_certificate_info'):
                            # Mock return None to trigger failure
                            mock_get.return_value = None
                            
                            with pytest.raises(SystemExit) as exc_info:
                                main()
                            
                            assert exc_info.value.code == 1
                            captured = capsys.readouterr()
                            assert "Failed to retrieve certificate" in captured.err
    
    def test_main_file_argument_nonexistent(self, capsys):
        """Test CLI with --file argument for non-existent file."""
        with patch('sys.argv', ['tlscope', '--file', '/nonexistent/cert.pem']):
            with patch('tlscope.cert.CertAnalyzer.load_cert_from_file') as mock_load:
                mock_load.return_value = None
                
                with pytest.raises(SystemExit) as exc_info:
                    main()
                
                assert exc_info.value.code == 1
                captured = capsys.readouterr()
                assert "Failed to retrieve certificate" in captured.err
    
    def test_main_url_with_port(self):
        """Test CLI with URL containing port."""
        with patch('sys.argv', ['tlscope', '--url', 'example.com:8443']):
            with patch('tlscope.cert.CertAnalyzer.get_cert_from_url') as mock_get:
                with patch('tlscope.cert.CertAnalyzer.parse_certificate') as mock_parse:
                    with patch('tlscope.cert.CertAnalyzer.analyze_certificate') as mock_analyze:
                        with patch('tlscope.cert.CertAnalyzer.print_certificate_info'):
                            # Setup mocks to succeed
                            mock_get.return_value = (b"cert_data", "TLSv1.3")
                            mock_cert = Mock()
                            mock_parse.return_value = mock_cert
                            mock_analyze.return_value = {
                                "is_valid": True,
                                "has_expired": False,
                                "tls_version": "TLSv1.3"
                            }
                            
                            main()
                            
                            # Verify port 8443 was used
                            mock_get.assert_called_once()
                            call_args = mock_get.call_args
                            assert call_args[0][0] == "example.com"
                            assert call_args[0][1] == 8443
    
    def test_main_https_url(self):
        """Test CLI with full HTTPS URL."""
        with patch('sys.argv', ['tlscope', '--url', 'https://example.com']):
            with patch('tlscope.cert.CertAnalyzer.get_cert_from_url') as mock_get:
                with patch('tlscope.cert.CertAnalyzer.parse_certificate') as mock_parse:
                    with patch('tlscope.cert.CertAnalyzer.analyze_certificate') as mock_analyze:
                        with patch('tlscope.cert.CertAnalyzer.print_certificate_info'):
                            mock_get.return_value = (b"cert_data", "TLSv1.3")
                            mock_cert = Mock()
                            mock_parse.return_value = mock_cert
                            mock_analyze.return_value = {
                                "is_valid": True,
                                "has_expired": False,
                            }
                            
                            main()
                            
                            # Verify hostname was extracted correctly
                            mock_get.assert_called_once()
                            call_args = mock_get.call_args
                            assert call_args[0][0] == "example.com"
                            assert call_args[0][1] == 443
    
    def test_main_custom_timeout(self):
        """Test CLI with custom timeout."""
        with patch('sys.argv', ['tlscope', '--url', 'example.com', '--timeout', '5']):
            with patch('tlscope.cert.CertAnalyzer.get_cert_from_url') as mock_get:
                with patch('tlscope.cert.CertAnalyzer.parse_certificate') as mock_parse:
                    with patch('tlscope.cert.CertAnalyzer.analyze_certificate') as mock_analyze:
                        with patch('tlscope.cert.CertAnalyzer.print_certificate_info'):
                            mock_get.return_value = (b"cert_data", "TLSv1.3")
                            mock_cert = Mock()
                            mock_parse.return_value = mock_cert
                            mock_analyze.return_value = {
                                "is_valid": True,
                                "has_expired": False,
                            }
                            
                            main()
                            
                            # Verify timeout was passed
                            mock_get.assert_called_once()
                            call_args = mock_get.call_args
                            assert call_args[0][2] == 5  # timeout parameter
    
    def test_main_verbose_flag(self):
        """Test CLI with verbose flag."""
        with patch('sys.argv', ['tlscope', '--url', 'example.com', '--verbose']):
            with patch('tlscope.cert.CertAnalyzer.get_cert_from_url') as mock_get:
                with patch('tlscope.cert.CertAnalyzer.parse_certificate') as mock_parse:
                    with patch('tlscope.cert.CertAnalyzer.analyze_certificate') as mock_analyze:
                        with patch('tlscope.cert.CertAnalyzer.print_certificate_info') as mock_print:
                            mock_get.return_value = (b"cert_data", "TLSv1.3")
                            mock_cert = Mock()
                            mock_parse.return_value = mock_cert
                            mock_analyze.return_value = {
                                "is_valid": True,
                                "has_expired": False,
                                "tls_version": "TLSv1.3"
                            }
                            
                            main()
                            
                            # Verify verbose=True was passed
                            mock_print.assert_called_once()
                            call_args = mock_print.call_args
                            assert call_args[0][1] is True  # verbose parameter
    
    def test_main_expired_certificate_exit_code(self):
        """Test CLI exits with error code for expired certificate."""
        with patch('sys.argv', ['tlscope', '--url', 'example.com']):
            with patch('tlscope.cert.CertAnalyzer.get_cert_from_url') as mock_get:
                with patch('tlscope.cert.CertAnalyzer.parse_certificate') as mock_parse:
                    with patch('tlscope.cert.CertAnalyzer.analyze_certificate') as mock_analyze:
                        with patch('tlscope.cert.CertAnalyzer.print_certificate_info'):
                            mock_get.return_value = (b"cert_data", "TLSv1.3")
                            mock_cert = Mock()
                            mock_parse.return_value = mock_cert
                            mock_analyze.return_value = {
                                "is_valid": False,
                                "has_expired": True,
                            }
                            
                            with pytest.raises(SystemExit) as exc_info:
                                main()
                            
                            assert exc_info.value.code == 1
    
    def test_main_invalid_certificate_exit_code(self):
        """Test CLI exits with error code for invalid certificate."""
        with patch('sys.argv', ['tlscope', '--url', 'example.com']):
            with patch('tlscope.cert.CertAnalyzer.get_cert_from_url') as mock_get:
                with patch('tlscope.cert.CertAnalyzer.parse_certificate') as mock_parse:
                    with patch('tlscope.cert.CertAnalyzer.analyze_certificate') as mock_analyze:
                        with patch('tlscope.cert.CertAnalyzer.print_certificate_info'):
                            mock_get.return_value = (b"cert_data", "TLSv1.3")
                            mock_cert = Mock()
                            mock_parse.return_value = mock_cert
                            mock_analyze.return_value = {
                                "is_valid": False,
                                "has_expired": False,
                            }
                            
                            with pytest.raises(SystemExit) as exc_info:
                                main()
                            
                            assert exc_info.value.code == 1
    
    def test_main_parse_certificate_failure(self, capsys):
        """Test CLI handles certificate parsing failure."""
        with patch('sys.argv', ['tlscope', '--url', 'example.com']):
            with patch('tlscope.cert.CertAnalyzer.get_cert_from_url') as mock_get:
                with patch('tlscope.cert.CertAnalyzer.parse_certificate') as mock_parse:
                    mock_get.return_value = (b"cert_data", "TLSv1.3")
                    mock_parse.return_value = None
                    
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    
                    assert exc_info.value.code == 1
                    captured = capsys.readouterr()
                    assert "Failed to parse certificate" in captured.err
