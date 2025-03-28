import socket
import ssl

def start_generic_tls_server():
    host = '127.0.0.1'
    port = 59  # Use any available port for testing Generic TLS
    certfile = "/home/kali/server-cert.pem"  # Path to your certificate file (PEM)
    keyfile = "/home/kali/server-key.pem"     # Path to your private key file (PEM)

    # Create a standard TCP socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.bind((host, port))
    sock.listen(5)
    print(f"Generic TLS Server started on {host}:{port}")

    # Create an SSL context using TLS.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    while True:
        # Accept a new connection.
        client_socket, client_address = sock.accept()
        print(f"Connection from {client_address} established.")
        try:
            # Wrap the client socket to enable TLS.
            tls_conn = context.wrap_socket(client_socket, server_side=True)
            # Read up to 1024 bytes from the client.
            data = tls_conn.recv(1024)
            print("Received data:\n", data)
            # Only respond if the received data exactly equals the generic probe.
            if data == b"\r\n\r\n\r\n\r\n":
                response = b"Response to Generic TLS server probe"
                tls_conn.sendall(response)
            # Otherwise, do nothing (no response is sent)
            tls_conn.close()
        except ssl.SSLError as e:
            print("SSL error:", e)
            client_socket.close()

if __name__ == "__main__":
    start_generic_tls_server()
