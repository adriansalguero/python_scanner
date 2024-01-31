import argparse
import ipaddress
import socket
import subprocess
import signal
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX

# Global variable to track whether the user pressed Ctrl-C
interrupted = False

def handle_ctrl_c(signum, frame):
    global interrupted
    interrupted = True
    print("\nScan interrupted by user.")
    exit(0)

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
        subprocess.check_output(['ping', '-c', '1', ip], stderr=subprocess.STDOUT, text=True)
        print(f"{GREEN}[+] {ip} is reachable (ICMP ping)    {RESET}")
    except subprocess.CalledProcessError:
        print(f"{RED}[-] {ip} is not reachable (ICMP ping)  {RESET}")

def scan_ports_threaded(ip, ports):
    with ThreadPoolExecutor() as executor:
        executor.map(lambda port: port_scan(ip, port), ports)

def main(host, ping, dns, port_range, num_threads):
    signal.signal(signal.SIGINT, handle_ctrl_c)

    if not host:
        print("Please provide a host or CIDR range using --host option.")
        return

    if ping and dns:
        print("Please choose either --ping or --dns, not both.")
        return

    try:
        network = ipaddress.ip_network(host, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
    except ValueError:
        ip_list = [host]

    if not ping and not dns:
        try:
            start_port, end_port = map(int, port_range.split('-'))
            ports = range(start_port, end_port + 1)
        except ValueError:
            print("Invalid port range format. Please provide a valid range (e.g., 1-100).")
            return

    for ip in ip_list:
        if interrupted:
            break

        print(f"Scanning ports for {ip}:")

        if dns:
            dns_resolve(ip)
        elif ping:
            icmp_ping(ip)
        else:
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

    if ping and dns:
        print("Please choose either --ping or --dns, not both.")
    else:
        main(host, ping, dns, port_range, num_threads)
