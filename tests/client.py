import ssl
import requests

from tls_analyzer.tls import TLSAnalyzer

class SecureHTTPClient:
    def __init__(self, url="https://localhost:8443", client_cert="client.pem", client_key="client.key", ca_file="ca.pem"):
        self.url = url
        self.client_cert = client_cert
        self.client_key = client_key
        self.ca_file = ca_file
        
    def create_ssl_context(self):
        # Create SSL context for TLS client
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Load client certificate and key for mutual TLS
        context.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
        
        # Load CA certificate to verify server
        context.load_verify_locations(cafile=self.ca_file)
        
        # Set minimum TLS version to 1.2 (this replaces deprecated OP_NO_TLS options)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Verify server certificate
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        return context
    
    def make_request(self):
        try:
            print(f"Connecting to {self.url}")
            print("Client will present certificate for mutual TLS authentication")
            
            # Create SSL context
            ssl_context = self.create_ssl_context()
            
            tls_analyzer = TLSAnalyzer(ssl_context)
            print(f"Using TLS protocol: {tls_analyzer.get_protocol()}")
            print(f"Enabled cipher suites: {', '.join(tls_analyzer.get_enabled_cipher_suites())}")
            
            # Make request with client certificate and CA verification
            response = requests.get(
                self.url,
                cert=(self.client_cert, self.client_key),
                verify=self.ca_file
            )
            
            print(f"\nStatus Code: {response.status_code}")
            print(f"Response: {response.text}")
            
            return response
            
        except FileNotFoundError as e:
            print(f"Certificate file not found: {e}")
            print("Please ensure you have the following files:")
            print(f"- Client certificate: {self.client_cert}")
            print(f"- Client private key: {self.client_key}")
            print(f"- CA certificate: {self.ca_file}")
        except requests.exceptions.SSLError as e:
            print(f"SSL Error: {e}")
        except requests.exceptions.ConnectionError as e:
            print(f"Connection Error: {e}")
        except Exception as e:
            print(f"Client error: {e}")

def main():
    # Create and run the secure client
    client = SecureHTTPClient(
        url="https://localhost:8443",
        client_cert="client.pem",
        client_key="client.key",
        ca_file="ca.pem"
    )
    client.make_request()

if __name__ == "__main__":
    main()