import argparse
import socket
import ssl
import sys
from time import sleep
# sudo python3 tcpscan.py 127.0.0.1 -p 50-60
# Import Scapy for the SYN scanning part.

from scapy.all import IP, TCP, sr1, send, conf

# Turn off Scapy verbose output
conf.verb = 0

# --- SYN scanning using Scapy ---
def syn_scan(target, port):
    """
    Send a SYN packet to target:port and check if we get a SYN/ACK.
    Returns True if the port is open, False otherwise.
    """
    pkt = IP(dst=target) / TCP(dport=port, flags="S")
    response = sr1(pkt, timeout=1, verbose=False)
    if response is None:
        return False
    if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:  # SYN/ACK flag
        # Send RST to close connection
        rst = IP(dst=target) / TCP(dport=port, flags="R")
        send(rst, verbose=False)
        return True
    return False

# --- Helper functions for fingerprinting ---
def try_tcp_immediate(target, port):
    """Attempt a plain TCP connection and immediately read up to 1024 bytes."""
    try:
        sock = socket.create_connection((target, port), timeout=3)
        sock.settimeout(3)
        data = sock.recv(1024)
        sock.close()
        return data
    except Exception:
        return b''

def try_tls_immediate(target, port):
    """Attempt a TLS connection (with handshake) and immediately read up to 1024 bytes."""
    try:
        context = ssl._create_unverified_context()
        sock = socket.create_connection((target, port), timeout=3)
        tls = context.wrap_socket(sock, server_hostname=target)
        tls.settimeout(3)
        data = tls.recv(1024)
        tls.close()
        return data
    except Exception:
        return b''

def probe_tcp_get(target, port):
    """Connect via plain TCP, send a GET request, and wait for a response."""
    try:
        sock = socket.create_connection((target, port), timeout=3)
        sock.settimeout(3)
        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        data = sock.recv(1024)
        sock.close()
        return data
    except Exception:
        return b''
    
def probe_tls_get(target, port):
    """Connect via TLS, send a GET request, and wait for a response."""
    try:
        context = ssl._create_unverified_context()
        sock = socket.create_connection((target, port), timeout=3)
        tls = context.wrap_socket(sock, server_hostname=target)
        tls.settimeout(3)
        tls.sendall(b"GET / HTTP/1.0\r\n\r\n")
        data = tls.recv(1024)
        tls.close()
        return data
    except Exception:
        return b''

def probe_tcp_generic(target, port):
    """Connect via plain TCP, send a generic probe, and wait for a response."""
    try:
        sock = socket.create_connection((target, port), timeout=3)
        sock.settimeout(3)
        sock.sendall(b"\r\n\r\n\r\n\r\n")
        data = sock.recv(1024)
        sock.close()
        return data
    except Exception:
        return b''

def probe_tls_generic(target, port):
    """Connect via TLS, send a generic probe, and wait for a response."""
    try:
        context = ssl._create_unverified_context()
        sock = socket.create_connection((target, port), timeout=3)
        tls = context.wrap_socket(sock, server_hostname=target)
        tls.settimeout(3)
        tls.sendall(b"\r\n\r\n\r\n\r\n")
        data = tls.recv(1024)
        tls.close()
        return data
    except Exception:
        return b''

'''def fingerprint_port(target, port):
    """
    Attempts to fingerprint the service running on an open port.
    Returns a tuple: (type_number, response_bytes)
    Where type_number corresponds to:
      1) TCP server-initiated
      2) TLS server-initiated
      3) HTTP server (client-initiated GET over TCP)
      4) HTTPS server (client-initiated GET over TLS)
      5) Generic TCP server (client-initiated generic probe over TCP)
      6) Generic TLS server (client-initiated generic probe over TLS)
    """
    # check immediate response over plain TCP.
    data = try_tcp_immediate(target, port)
    if data:
        # Heuristically, if the first byte is 0x16 (decimal 22), it might be TLS handshake.
        if len(data) > 0 and data[0] == 22:
            return 2, data  # TLS server-initiated
        else:
            return 1, data  # TCP server-initiated

    # check immediate response over TLS.
    data = try_tls_immediate(target, port)
    if data:
        return 2, data
    
    # client-initiated probe: GET request over plain TCP.
    data = probe_tcp_get(target, port)
    if data:
        return 3, data
    
    # client-initiated probe: GET request over TLS.
    data = probe_tls_get(target, port)
    if data:
        return 4, data
    
    # client-initiated probe: Generic probe over plain TCP.
    data = probe_tcp_generic(target, port)
    if data:
        return 5, data

    # client-initiated probe: Generic probe over TLS.
    data = probe_tls_generic(target, port)
    if data:
        return 6, data

    return None, b''
'''

def fingerprint_port(target, port):
    """
    Attempts to fingerprint the service running on an open port.
    Returns a tuple: (type_number, response_bytes)
    Where type_number corresponds to:
      1) TCP server-initiated
      2) TLS server-initiated
      3) HTTP server (client-initiated GET over TCP)
      4) HTTPS server (client-initiated GET over TLS)
      5) Generic TCP server (client-initiated generic probe over TCP)
      6) Generic TLS server (client-initiated generic probe over TLS)
    """

    # 1. Try immediate TLS handshake (server-initiated over TLS).
    data = try_tls_immediate(target, port)
    if data:
        return 2, data

    # 2. Try immediate TCP handshake (server-initiated over plain TCP).
    data = try_tcp_immediate(target, port)
    if data:
        # If it looks like a TLS handshake message, then classify as TLS server-initiated.
        if len(data) > 0 and data[0] == 22:
            return 2, data
        else:
            return 1, data

    # 3. Client-initiated probe: GET request over TLS.
    data = probe_tls_get(target, port)
    if data:
        return 4, data

    # 4. Client-initiated probe: GET request over plain TCP.
    data = probe_tcp_get(target, port)
    if data:
        return 3, data

    # 5. Client-initiated probe: Generic probe over plain TCP.
    data = probe_tcp_generic(target, port)
    if data:
        return 5, data

    # 6. Client-initiated probe: Generic probe over TLS.
    data = probe_tls_generic(target, port)
    if data:
        return 6, data

    return None, b''

def make_printable(data):
    """Converts bytes to a string with non-printable bytes replaced by '.'."""
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)

def main():
    parser = argparse.ArgumentParser(
        description="tcpscan: TCP SYN scan and service fingerprinting tool"
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 80 or 1000-2000)", default=None)
    args = parser.parse_args()

    target = args.target

    # Determine which ports to scan.
    if args.ports:
        if '-' in args.ports:
            try:
                start, end = args.ports.split('-')
                ports = list(range(int(start), int(end) + 1))
            except ValueError:
                sys.exit("Invalid port range. Use the form X-Y (e.g., 1000-2000).")
        else:
            try:
                ports = [int(args.ports)]
            except ValueError:
                sys.exit("Invalid port number.")
    else:
        ports = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]

    print("[*] Starting SYN scan on target:", target)
    open_ports = []
    for port in ports:
        sys.stdout.write("Scanning port {} ... ".format(port))
        sys.stdout.flush()
        if syn_scan(target, port):
            print("open")
            open_ports.append(port)
        else:
            print("closed/filtered")

    if not open_ports:
        print("No open ports found.")
        return

    print("\n[*] Open ports:", open_ports)
    print("[*] Starting service fingerprinting on open ports...\n")
    for port in open_ports:
        print("Host: {}:{}".format(target, port))
        type_num, response = fingerprint_port(target, port)
        types = {
            1: "TCP server-initiated",
            2: "TLS server-initiated",
            3: "HTTP server",
            4: "HTTPS server",
            5: "Generic TCP server",
            6: "Generic TLS server"
        }
        type_str = types.get(type_num, "Unknown/No Response")
        printable_response = make_printable(response) if response else ""
        print("Type: ({}) {}".format(type_num if type_num is not None else "-", type_str))
        print("Response: {}\n".format(printable_response))
        # Small pause to avoid overwhelming target
        sleep(0.5)

if __name__ == "__main__":
    main()
