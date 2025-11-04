import ssl
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from tls_analyzer.tls import TLSAnalyzer

class SecureHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # Get client certificate information
        client_cert = self.connection.getpeercert()
        if client_cert:
            subject = dict(x[0] for x in client_cert['subject'])
            client_cn = subject.get('commonName', 'Unknown')
            message = f"<h1>Secure mTLS Server</h1><p>Hello, {client_cn}!</p><p>Client certificate verified successfully.</p>"
        else:
            message = "<h1>Secure mTLS Server</h1><p>No client certificate provided.</p>"
        
        self.wfile.write(message.encode())

class SecureHTTPServer:
    def __init__(self, port=8443, certfile="server.pem", keyfile="server.key", ca_file="ca.pem"):
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.ca_file = ca_file
        self.server = None
        
    def create_ssl_context(self):
        # Create SSL context for TLS server
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Load server certificate and key
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        
        # Configure for mutual TLS (client certificate verification)
        context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate
        context.load_verify_locations(cafile=self.ca_file)  # Load CA to verify client certs
        
        # Security options - disable older TLS versions
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        
        # Set minimum TLS version to 1.2
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        return context
    
    def start_server(self):
        try:
            # Create HTTP server
            self.server = HTTPServer(('localhost', self.port), SecureHTTPRequestHandler)
            
            # Create SSL context and wrap the socket
            ssl_context = self.create_ssl_context()
            self.server.socket = ssl_context.wrap_socket(
                self.server.socket,
                server_side=True
            )
            
            print(f"Starting secure mTLS server on https://localhost:{self.port}")
            print("Server requires client certificate verification")
            
            tls_analyzer = TLSAnalyzer(ssl_context)
            print(f"Using TLS protocol: {tls_analyzer.get_protocol()}")
            print(f"Enabled cipher suites: {', '.join(tls_analyzer.get_enabled_cipher_suites())}")
            
            print("Press Ctrl+C to stop the server")
            
            # Start serving requests
            self.server.serve_forever()
            
        except FileNotFoundError as e:
            print(f"Certificate file not found: {e}")
            print("Please ensure you have the following files:")
            print(f"- Server certificate: {self.certfile}")
            print(f"- Server private key: {self.keyfile}")
            print(f"- CA certificate: {self.ca_file}")
        except ssl.SSLError as e:
            print(f"SSL configuration error: {e}")
        except KeyboardInterrupt:
            print("\nShutting down server...")
            if self.server:
                self.server.shutdown()
        except Exception as e:
            print(f"Server error: {e}")

def main():
    # Create and start the secure server
    server = SecureHTTPServer(
        port=8443,
        certfile="server.pem",
        keyfile="server.key", 
        ca_file="ca.pem"
    )
    server.start_server()

if __name__ == "__main__":
    main()