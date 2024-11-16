import os
import nmap
import csv
import json
import time

def scan_network(nm):
    print("Scanning the network...")
    nm.scan(hosts='192.168.1.0/24', arguments='-sn')

    print("Found IPs:")
    for host in nm.all_hosts():
        print(f'IP: {host} - Status: {nm[host].state()}')

def scan_network_with_open_ports(nm):
    print("Scanning the network...")
    nm.scan(hosts='192.168.1.0/24', arguments='-p- -T4 -sV -O')

    print("Found IPs with open ports:")
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f'\nIP: {host} - Status: {nm[host].state()}')
            print(f'  Operating System: {nm[host].get("osclass", "Unknown")}')
            
            for proto in nm[host].all_protocols():
                print(f'  Protocol: {proto}')
                
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service = nm[host][proto][port].get('name', 'Unknown')
                        version = nm[host][proto][port].get('version', 'Unknown')
                        print(f'    Port: {port} -> Status: {state} -> Service: {service} -> Version: {version}')

def scan_custom_range(ip_range, port_range, nm):
    print(f"Scanning the IP range: {ip_range} and ports: {port_range}...")
    nm.scan(hosts=ip_range, arguments=f'-p {port_range} -T4 -sV -O')

    print("Found IPs with open ports:")
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f'\nIP: {host} - Status: {nm[host].state()}')
            print(f'  Operating System: {nm[host].get("osclass", "Unknown")}')
            
            for proto in nm[host].all_protocols():
                print(f'  Protocol: {proto}')
                
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service = nm[host][proto][port].get('name', 'Unknown')
                        version = nm[host][proto][port].get('version', 'Unknown')
                        print(f'    Port: {port} -> Status: {state} -> Service: {service} -> Version: {version}')

def save_results_csv(nm):
    with open('results.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP', 'Port', 'Status', 'Service', 'Version', 'Operating System'])

        for host in nm.all_hosts():
            if nm[host].state() == "up":
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto]:
                        state = nm[host][proto][port]['state']
                        if state == 'open':
                            service = nm[host][proto][port].get('name', 'Unknown')
                            version = nm[host][proto][port].get('version', 'Unknown')
                            os_info = nm[host].get('osclass', 'Unknown')
                            writer.writerow([host, port, state, service, version, os_info])

def save_results_json(nm):
    data = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service = nm[host][proto][port].get('name', 'Unknown')
                        version = nm[host][proto][port].get('version', 'Unknown')
                        os_info = nm[host].get('osclass', 'Unknown')
                        data.append({
                            "IP": host,
                            "Port": port,
                            "Status": state,
                            "Service": service,
                            "Version": version,
                            "Operating System": os_info
                        })
    
    with open('results.json', 'w') as json_file:
        json.dump(data, json_file, indent=4)

def quick_scan(nm):
    print("Quick scan (common ports only)...")
    nm.scan(hosts='192.168.1.0/24', arguments='-p 22,80,443 -T4')

    print("Found IPs with open ports:")
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f'IP: {host} - Status: {nm[host].state()}')
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service = nm[host][proto][port].get('name', 'Unknown')
                        print(f'  Port: {port} -> Status: {state} -> Service: {service}')

def scan_with_scripts(nm):
    print("Scanning with Nmap scripts...")
    nm.scan(hosts='192.168.1.0/24', arguments='--script default -T4')

    print("Found IPs with open ports:")
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f'IP: {host} - Status: {nm[host].state()}')
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service = nm[host][proto][port].get('name', 'Unknown')
                        print(f'  Port: {port} -> Status: {state} -> Service: {service}')

def scan_ports_by_status(nm):
    print("Scanning ports by status...")
    nm.scan(hosts='192.168.1.0/24', arguments='-p- -T4')

    status = input("Enter the port status to filter (open/closed/filtered): ").strip()
    
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f'\nIP: {host} - Status: {nm[host].state()}')
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == status:
                        service = nm[host][proto][port].get('name', 'Unknown')
                        print(f'  Port: {port} -> Status: {state} -> Service: {service}')

def verify_open_ports_and_service(nm):
    ip = input("Enter the device's IP address: ")
    port = input("Enter the port to verify: ")
    nm.scan(hosts=ip, arguments=f'-p {port} -sV')
    print(f'Status of port {port}: {nm[ip]["tcp"][int(port)]["state"]}')
    print(f'Service: {nm[ip]["tcp"][int(port)]["name"]}')

def scheduled_scan(interval, nm):
    while True:
        print("Starting scan...")
        scan_network_with_open_ports(nm)
        print(f"Waiting {interval} seconds for the next scan...")
        time.sleep(interval)

os.system('cls||clear')

def display_menu():
    print("\033[31m ▄▄▄       █    ██ ▄▄▄█████▓ ▒█████   ███▄    █  ███▄ ▄███▓ ▄▄▄       ██▓███ \033[0m")
    print("\033[31m▒████▄     ██  ▓██▒▓  ██▒ ▓▒▒██▒  ██▒ ██ ▀█   █ ▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒\033[0m")
    print("\033[31m▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██░  ██▒▓██  ▀█ ██▒▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒\033[0m")
    print("\033[31m░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ▒██   ██░▓██▒  ▐▌██▒▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒\033[0m")
    print("\033[31m ▓█   ▓██▒▒▒█████▓   ▒██▒ ░ ░ ████▓▒░▒██░   ▓██░▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░\033[0m")
    print("\033[31m▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░\033[0m")
    print("\033[31m ▒   ▒▒ ░░░▒░ ░ ░     ░      ░ ▒ ▒░ ░ ░░   ░ ▒░░  ░      ░  ▒   ▒▒ ░░▒ ░     \033[0m")
    print("\033[31m ░   ▒    ░░░ ░ ░   ░      ░ ░ ░ ▒     ░   ░ ░ ░      ░     ░   ▒   ░░       \033[0m")
    print("\033[31m ░  ░   ░                  ░ ░           ░        ░         ░  ░         \033[0m")

    print("\033[32m This tool is made for educational and testing purposes. The author of this tool is not responsible for any damage caused by its use.\033[0m")
    print("\033[31m DONT BE A SKID\033[0m")



    print("1. Scan the network")
    print("2. Scan the network with open ports")
    print("3. Scan a custom range of IPs and ports")
    print("4. Save results to CSV or JSON file")
    print("5. Quick scan (common ports only)")
    print("6. Scan with Nmap scripts (--script)")
    print("7. Configure scan priority and timing (-T)")
    print("8. Filter results by port status")
    print("9. Verify open ports with specific service")
    print("10. Scheduled or automatic scanning")
    print("11. Exit")

def main():
    nm = nmap.PortScanner()
    while True:
        display_menu()
        option = input("Enter your option: ")
        
        if option == '1':
            scan_network(nm)
        elif option == '2':
            scan_network_with_open_ports(nm)
        elif option == '3':
            ip_range = input("Enter the IP range (e.g., 192.168.1.0/24): ")
            port_range = input("Enter the port range (e.g., 22-80): ")
            scan_custom_range(ip_range, port_range, nm)
        elif option == '4':
            file_type = input("Select file type (csv/json): ")
            if file_type == 'csv':
                save_results_csv(nm)
            elif file_type == 'json':
                save_results_json(nm)
            else:
                print("Invalid option.")
        elif option == '5':
            quick_scan(nm)
        elif option == '6':
            scan_with_scripts(nm)
        elif option == '7':
            priority = input("Enter the priority (0-5): ")
            nm.scan(hosts='192.168.1.0/24', arguments=f'-T{priority} -p- -sV -O')
            print("Scan completed with configured priority.")
        elif option == '8':
            scan_ports_by_status(nm)
        elif option == '9':
            verify_open_ports_and_service(nm)
        elif option == '10':
            interval = int(input("Enter the interval in seconds for scheduled scanning: "))
            scheduled_scan(interval, nm)
        elif option == '11':
            print("Exiting...")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
