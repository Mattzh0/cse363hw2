import socket
import ssl

def start_https_server():
    host = '127.0.0.1'
    port = 56 
    certfile = "/home/kali/server-cert.pem" 
    keyfile = "/home/kali/server-key.pem"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.bind((host, port))
    sock.listen(1)
    print(f"HTTPS Server started on {host}:{port}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    while True:
        client_socket, client_address = sock.accept()
        print(f"Connection from {client_address} established.")
        try:
            tls_conn = context.wrap_socket(client_socket, server_side=True)
            request = tls_conn.recv(1024).decode('utf-8', errors='replace')
            print("Received request:\n", request)

            # if a valid GET request is received, send a response.
            if request.startswith("GET"):
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "Welcome to the HTTPS server!"
                )
            else:
                response = (
                    "HTTP/1.1 400 Bad Request\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "Invalid Request"
                )
            tls_conn.sendall(response.encode('utf-8'))
            tls_conn.shutdown(socket.SHUT_RDWR)
            tls_conn.close()
        except ssl.SSLError as e:
            print("SSL error:", e)
            client_socket.close()

if __name__ == "__main__":
    start_https_server()
