import socket

target = input("Enter target IP (example: 127.0.0.1): ")
start_port = int(input("Enter start port: "))
end_port = int(input("Enter end port: "))

print(f"\nScanning {target} from port {start_port} to {end_port}...\n")

open_ports = []

for port in range(start_port, end_port + 1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    result = sock.connect_ex((target, port))

    if result == 0:
        open_ports.append(port)

    sock.close()

if open_ports:
    print("Open ports found:")
    for port in open_ports:
        print(f"Port {port} is OPEN")
else:
    print("No open ports found.")
