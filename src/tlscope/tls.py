"""TLS/SSL Certificate Analyzer

Analyzes TLS/SSL certificates from URLs or local files and displays detailed information
including validity, issuer, subject, SANs, and security properties.
"""

import ssl
from typing import List, Union



class TLSAnalyzer:
    def __init__(self, ssl_obj: Union[ssl.SSLSocket, ssl.SSLContext]):
        self.ssl_obj = ssl_obj

    def get_protocol(self) -> str:
        """Return the TLS protocol version.

        For SSLSocket: returns the negotiated TLS version (e.g., 'TLSv1.3')
        For SSLContext: returns the minimum TLS version configured
        """
        if isinstance(self.ssl_obj, ssl.SSLSocket):
            version = self.ssl_obj.version()
            return version if version else "Unknown"
        elif isinstance(self.ssl_obj, ssl.SSLContext):
            # For SSLContext, return the minimum version configured
            min_version = self.ssl_obj.minimum_version
            if min_version == ssl.TLSVersion.TLSv1_2:
                return "TLSv1.2+"
            elif min_version == ssl.TLSVersion.TLSv1_3:
                return "TLSv1.3+"
            elif min_version == ssl.TLSVersion.TLSv1_1:
                return "TLSv1.1+"
            elif min_version == ssl.TLSVersion.TLSv1:
                return "TLSv1.0+"
            else:
                return "TLS (default)"
        else:
            return "Unknown"

    def get_enabled_cipher_suites(self) -> List[str]:
        """Return a list of TLS enabled cipher suites.

        For SSLSocket: returns the negotiated cipher suite
        For SSLContext: returns all enabled cipher suites

        Returns:
            List of cipher suite names
        """
        if isinstance(self.ssl_obj, ssl.SSLSocket):
            # For an active connection, return the negotiated cipher
            cipher = self.ssl_obj.cipher()
            if cipher:
                return [cipher[0]]  # cipher[0] is the cipher name
            return []
        elif isinstance(self.ssl_obj, ssl.SSLContext):
            # For SSLContext, return all enabled ciphers
            try:
                ciphers = self.ssl_obj.get_ciphers()
                return [cipher["name"] for cipher in ciphers]
            except AttributeError:
                # Fallback for older Python versions
                return []
        else:
            return []
