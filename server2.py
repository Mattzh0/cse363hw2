import socket
import ssl

def start_tls_server():
    host = '127.0.0.1'
    port = 51

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind((host, port))

    server_socket.listen(1)

    # wrap the socket with SSL (TLS)
    # create an SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # use a self signed certificate and private key just for testing purposes
    # make sure that the file directory and file names are correct
    context.load_cert_chain(certfile='/home/kali/server-cert.pem', keyfile='/home/kali/server-key.pem')

    print(f"TLS Server started on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        try:
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

        banner = b"Welcome to the TLS server!"
        try:
            tls_socket.send(banner)
        except Exception as e:
            print(f"Error sending banner to {client_address}: {e}")
        finally:
            tls_socket.close()

if __name__ == "__main__":
    start_tls_server()
