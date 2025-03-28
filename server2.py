import socket
import ssl

def start_tls_server():
    host = '127.0.0.1'
    port = 51

    # Create a basic TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind to host and port
    server_socket.bind((host, port))

    # Start listening for connections (max 1 in the backlog)
    server_socket.listen(1)

    # Wrap the socket with SSL (TLS)
    # Create an SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # Use a valid certificate and private key (or generate self-signed for testing)
    context.load_cert_chain(certfile='/home/kali/server-cert.pem', keyfile='/home/kali/server-key.pem')

    print(f"TLS Server started on {host}:{port}")

    while True:
        # Wait for a connection
        client_socket, client_address = server_socket.accept()
        try:
            # Attempt to wrap the connection with TLS.
            # This call will perform the handshake. If the client doesn't send the proper TLS handshake messages,
            # an ssl.SSLEOFError (or other handshake-related error) is raised.
            tls_socket = context.wrap_socket(client_socket, server_side=True)
        except ssl.SSLEOFError:
            print(f"Handshake failed with {client_address}: client did not complete TLS handshake properly")
            client_socket.close()
            continue
        except ssl.SSLError as e:
            print(f"SSL error with {client_address}: {e}")
            client_socket.close()
            continue

        print(f"Connection established with {client_address}")

        # Send an immediate response (banner)
        banner = b"Welcome to the TLS server!"
        try:
            tls_socket.send(banner)
        except Exception as e:
            print(f"Error sending banner to {client_address}: {e}")
        finally:
            tls_socket.close()

if __name__ == "__main__":
    start_tls_server()
