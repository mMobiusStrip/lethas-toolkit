import socket

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((ip, port))
            open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports
