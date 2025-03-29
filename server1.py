import socket

def start_tcp_server():
    host = '127.0.0.1'
    port = 50

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind((host, port))

    server_socket.listen(1)

    print(f"Server started on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address} established.")

        # send an immediate response (banner)
        banner = b"Welcome to the TCP server!"  # this is the immediate response
        client_socket.send(banner)

        client_socket.close()

if __name__ == "__main__":
    start_tcp_server()
