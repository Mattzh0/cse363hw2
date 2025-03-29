import socket
import sys

def start_http_server():
    host = '127.0.0.1'
    port = 52

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind((host, port))

    server_socket.listen(1)

    print(f"HTTP Server started on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address} established.")

        # receive the HTTP request (we expect the GET request)
        request = client_socket.recv(1024).decode('utf-8', errors='replace')
        print(f"Received request:\n{request}")

        # if the request is a valid HTTP GET request, send a response
        if request.startswith("GET"):
            response = """HTTP/1.1 200 OK\r
Content-Type: text/plain\r
\r
Welcome to the HTTP server!"""
        else:
            response = """HTTP/1.1 400 Bad Request\r
Content-Type: text/plain\r
\r
Invalid Request"""
        
        client_socket.sendall(response.encode('utf-8'))

        client_socket.close()

if __name__ == "__main__":
    start_http_server()
