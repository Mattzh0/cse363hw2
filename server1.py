import socket

def start_tcp_server():
    # Set up a TCP server on localhost (127.0.0.1) and port 50
    host = '127.0.0.1'
    port = 50

    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the host and port
    server_socket.bind((host, port))

    # Start listening for incoming connections (max 1 connection in the backlog)
    server_socket.listen(1)

    print(f"Server started on {host}:{port}")

    while True:
        # Accept incoming connections
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address} established.")

        # Send an immediate response (banner)
        banner = b"Welcome to the TCP server!"  # This is the immediate response
        client_socket.send(banner)

        # Close the client connection after sending the banner
        client_socket.close()

if __name__ == "__main__":
    start_tcp_server()
