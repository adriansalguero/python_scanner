import argparse
import ipaddress
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX

def calculate_checksum(message):
    # Function to calculate ICMP checksum
    checksum = 0
    count_to = (len(message) // 2) * 2
    count = 0

    while count < count_to:
        this_val = message[count + 1] * 256 + message[count]
        checksum += this_val
        checksum &= 0xffffffff
        count += 2

    if count_to < len(message):
        checksum += message[len(message) - 1]
        checksum &= 0xffffffff

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    checksum = ~checksum
    checksum &= 0xffff

    return checksum

def dns_resolve(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
        print(f"{GREEN}[+] {ip} resolves to {host} (DNS resolution)    {RESET}")
    except socket.herror:
        print(f"{RED}[-] Unable to resolve {ip} (DNS resolution)    {RESET}")

def port_scan(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=1) as sock:
            print(f"{GREEN}[+] {ip:15}:{port:5} is open    {RESET}")
    except (socket.error, OSError):
        print(f"{RED}[-] {ip:15}:{port:5} is closed  {RESET}")

def icmp_ping(ip):
    try:
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_socket.settimeout(1)
        icmp_id = 12345
        sequence = 1
        payload = b'PingTestPayload'

        # ICMP Header
        icmp_type = 8  # ICMP Echo Request
        code = 0
        checksum = 0
        header = struct.pack('!BBHHH', icmp_type, code, checksum, icmp_id, sequence)
        payload_checksum = calculate_checksum(header + payload)

        # ICMP Packet
        icmp_packet = struct.pack('!BBHHH', icmp_type, code, socket.htons(payload_checksum), icmp_id, sequence) + payload

        # Send ICMP packet
        icmp_socket.sendto(icmp_packet, (ip, 0))

        # Receive ICMP response
        start_time = time.time()
        response, _ = icmp_socket.recvfrom(1024)
        end_time = time.time()

        # Check if the received packet is an ICMP Echo Reply
        response_type = struct.unpack('!B', response[20:21])[0]
        if response_type == 0:  # ICMP Echo Reply
            print(f"{GREEN}[+] {ip} is reachable (ICMP ping)    {RESET}")
        else:
            print(f"{RED}[-] {ip} is not reachable (ICMP ping)  {RESET}")

        icmp_socket.close()

    except socket.error:
        print(f"{RED}[-] {ip} is not reachable (ICMP ping)  {RESET}")

def scan_ports_threaded(ip, ports):
    with ThreadPoolExecutor() as executor:
        executor.map(lambda port: port_scan(ip, port), ports)

def main(host, ping, dns, port_range, num_threads):
    try:
        network = ipaddress.ip_network(host, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
    except ValueError:
        ip_list = [host]

    if dns:
        for ip in ip_list:
            dns_resolve(ip)
    elif ping:
        for ip in ip_list:
            icmp_ping(ip)
    else:
        try:
            start_port, end_port = map(int, port_range.split('-'))
            ports = range(start_port, end_port + 1)
        except ValueError:
            print("Invalid port range format. Please provide a valid range (e.g., 1-100).")
            return

        for ip in ip_list:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                print(f"Invalid IP address: {ip}")
                continue

            scan_ports_threaded(ip, ports)

        print("\nScan completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple port scanner")
    parser.add_argument("--host", "-H", dest="host", help="Host or CIDR range to scan.")
    parser.add_argument("--ping", "-P", dest="ping", action="store_true", help="Perform ICMP ping instead of port scanning.")
    parser.add_argument("--dns", "-D", dest="dns", action="store_true", help="Perform DNS resolution instead of port scanning.")
    parser.add_argument("--ports", "-p", dest="port_range", default="1-65535", help="Port range to scan, default is 1-65535 (all ports)")
    parser.add_argument("--threads", "-t", dest="num_threads", type=int, default=5, help="Number of threads to use, default is 5")
    args = parser.parse_args()
    host, ping, dns, port_range, num_threads = args.host, args.ping, args.dns, args.port_range, args.num_threads

    if not host:
        print("Please provide a host or CIDR range using --host option.")
    elif ping and dns:
        print("Please choose either --ping or --dns, not both.")
    else:
        try:
            main(host, ping, dns, port_range, num_threads)
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
