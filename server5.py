import socket

def start_generic_tcp_server():
    host = '127.0.0.1'
    port = 58

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind((host, port))

    server_socket.listen(1)

    print(f"Generic TCP Server started on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()

        data = client_socket.recv(1024)
        if data == b"\r\n\r\n\r\n\r\n":
            response = b"Response to Generic TCP server probe"
            client_socket.sendall(response)

        client_socket.close()

if __name__ == "__main__":
    start_generic_tcp_server()
