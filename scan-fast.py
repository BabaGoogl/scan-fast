import socket
import threading
import time
import sys
import queue
import os
from concurrent.futures import ThreadPoolExecutor

# Configuration
DEFAULT_TIMEOUT = 0.5
MAX_THREADS = 500
BATCH_SIZE = 100

def scan_port(target, port, timeout=DEFAULT_TIMEOUT):
    """Scan a single port with optimized socket creation"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def scan_batch(target, port_batch, results):
    """Scan a batch of ports and report open ones immediately"""
    for port in port_batch:
        if (open_port := scan_port(target, port)) is not None:
            results.put(open_port)
            print(f"Port\t {open_port}\t is open", flush=True)

def generate_batches(port_range, batch_size=BATCH_SIZE):
    """Generate port batches for parallel scanning"""
    start, end = port_range
    return [range(i, min(i+batch_size, end+1)) 
            for i in range(start, end+1, batch_size)]

def clear_console():
    """Clear the console based on the operating system"""
    os.system('cls' if os.name == 'nt' else 'clear')

def generate_nmap_commands(target, open_ports):
    """Generate nmap commands for the open ports"""
    commands = []
    if open_ports:
        # Single command for all open ports
        port_list = ','.join(map(str, open_ports))
        commands.append(f"nmap -p {port_list} -sV -sC -A {target}")
        
    return commands

def print_final_results(target, scan_duration, open_ports):
    """Print the final results after clearing the console"""
    clear_console()
    total_open = len(open_ports)
    
    print(f"\n[+] Scan of {target} completed in {scan_duration:.2f} seconds")
    print(f"[+] Total open ports found: {total_open}")
    
    if open_ports:
        print("\n[+] Open ports summary:")
        for port in open_ports:
            print(f"  - Port {port} is open")
        
        # Generate and display nmap commands
        nmap_commands = generate_nmap_commands(target, open_ports)
        print("\n[+] Suggested nmap commands for further investigation:")
        print(f"  - Comprehensive scan for all open ports:")
        print(f"    {nmap_commands[0]}")
        
        for cmd in nmap_commands[1:]:
            print(f"    {cmd}")
    else:
        print("[+] No open ports found")

def parse_port_range(port_range_str):
    """Parse port range string like '1-1000' into (start, end) tuple"""
    try:
        start, end = map(int, port_range_str.split('-'))
        if 1 <= start <= end <= 65535:
            return (start, end)
        raise ValueError
    except:
        print("Invalid port range. Use format like '1-1000' (1-65535)")
        sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print("Usage: python fast-scan.py <target_ip> -t <thread_level> [-r <port_range>]")
        print("Thread levels: 1-5 (higher = more aggressive scanning)")
        print("Port range: e.g., '1-1000' (default: 1-65535)")
        print("Example: python fast-scan.py 192.168.1.1 -t 4 -r 1-1000")
        sys.exit(1)

    target = sys.argv[1]
    thread_level = 1
    port_range = (1, 65535)  # Default port range
    
    # Parse command line arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "-t":
            try:
                thread_level = int(sys.argv[i+1])
                if thread_level < 1 or thread_level > 5:
                    raise ValueError
                i += 2
            except (ValueError, IndexError):
                print("Invalid thread level. Use 1-5")
                sys.exit(1)
        elif sys.argv[i] == "-r":
            try:
                port_range = parse_port_range(sys.argv[i+1])
                i += 2
            except IndexError:
                print("Missing port range after -r")
                sys.exit(1)
        else:
            i += 1

    # Adjust parameters based on thread level
    config = {
        1: {'timeout': 1.0, 'max_threads': 100},
        2: {'timeout': 0.8, 'max_threads': 200},
        3: {'timeout': 0.6, 'max_threads': 300},
        4: {'timeout': 0.4, 'max_threads': 400},
        5: {'timeout': 0.2, 'max_threads': 500}
    }
    
    timeout = config[thread_level]['timeout']
    max_threads = config[thread_level]['max_threads']

    print(f"\n[+] Scanning {target} with level {thread_level} configuration")
    print(f"[+] Port range: {port_range[0]}-{port_range[1]}")
    print(f"[+] Timeout: {timeout}s | Max threads: {max_threads}")
    print("[+] Starting scan...\n")

    results = queue.Queue()
    port_batches = generate_batches(port_range)
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for batch in port_batches:
            executor.submit(scan_batch, target, batch, results)

    scan_duration = time.time() - start_time
    open_ports = sorted(results.queue) if not results.empty() else []
    
    # Print final results after clearing console
    print_final_results(target, scan_duration, open_ports)

if __name__ == "__main__":
    main()