import socket

def scan_ports(host):

    ports = [21,22,80,443,3306]
    open_ports = []

    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(1)

            if s.connect_ex((host,p)) == 0:
                open_ports.append(p)

            s.close()

        except:
            pass

    return open_ports
