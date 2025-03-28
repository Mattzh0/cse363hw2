import socket

def start_generic_tcp_server():
    host = '127.0.0.1'
    port = 58  # Use any available port

    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind to host and port
    server_socket.bind((host, port))

    # Start listening for incoming connections
    server_socket.listen(1)

    print(f"Generic TCP Server started on {host}:{port}")

    while True:
        # Accept the incoming connection
        client_socket, client_address = server_socket.accept()

        # Receive data from the client (waiting for the generic probe)
        data = client_socket.recv(1024)
        if data == b"\r\n\r\n\r\n\r\n":
            # Only respond if the data matches the generic probe
            response = b"Response to Generic TCP server probe"
            client_socket.sendall(response)

        # Close the connection
        client_socket.close()

if __name__ == "__main__":
    start_generic_tcp_server()
