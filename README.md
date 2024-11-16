
# AutoNMAP - Network Scanner Tool

Welcome to **AutoNMAP**, an advanced and interactive network scanning tool built in Python. AutoNMAP utilizes the powerful Nmap library to perform comprehensive network assessments, including host discovery, port scanning, service identification, and vulnerability detection. Whether you're an IT professional, network administrator, or cybersecurity enthusiast, AutoNMAP is designed to simplify the process of scanning and analyzing networks with ease.

### Overview

With **AutoNMAP**, you can quickly scan local or custom IP ranges, identify open ports on devices, and save the results in various formats like CSV and JSON for further analysis. The tool also allows users to automate scans, utilize Nmap's scripting capabilities, and fine-tune scan priorities for more efficient results.

### Key Features

<ul>
  <li><strong><em>Network Scanning:</em></strong> Quickly discover active devices on your network or any custom IP range.</li>
  <li><strong><em>Port Scanning:</em></strong> Identify open ports and obtain service and version details for each discovered device.</li>
  <li><strong><em>Custom Range Scanning:</em></strong> Tailor the scan to specific IP and port ranges of your network, allowing for focused analysis.</li>
  <li><strong><em>Scripted Scans:</em></strong> Run advanced Nmap scripts for vulnerability detection, version detection, and other specialized tasks.</li>
  <li><strong><em>Export Results:</em></strong> Save scan results to CSV or JSON files for easy storage, analysis, and reporting.</li>
  <li><strong><em>Scheduled Scans:</em></strong> Automate network scans at custom intervals for continuous monitoring.</li>
  <li><strong><em>Interactive Menu:</em></strong> A simple, interactive menu-based interface for selecting and executing scans, making the tool accessible even for beginners.</li>
  <li><strong><em>Priority and Timing Configuration:</em></strong> Adjust scan timing and priority to control scan speed and resource usage.</li>
</ul>

### Installation & Usage

To begin using **AutoNMAP**, clone the repository and run the script as follows:

```bash
git clone https://github.com/nefrarius/AutoNMAP.git
cd AutoNMAP
pip3 install -r requirements.txt
python3 autonmap.py
```

Alternatively, run the english version of the script directly with:

```bash
python3 autonmap_ENG.py
```

### Example Commands

Just execute the tool and a menu will appear there with all the options it has.

### Modifying IP Range for Scanning

To modify the IP range for scanning, you can adjust the `scan_network()` function within the script. By default, it scans the local network (`192.168.1.0/24`). To scan a different IP range, simply change the `hosts` parameter within the function:

```python
# Default network scan for 192.168.1.0/24
nm.scan(hosts='192.168.1.0/24', arguments='-sn')

# Example: Modify to scan a custom IP range (e.g., 10.0.0.0/24)
nm.scan(hosts='10.0.0.0/24', arguments='-sn')
```

This allows you to tailor the tool to any network range you wish to scan.

### Scanning Options

Once you run the tool, you'll be presented with an interactive menu, offering the following options:

1. **Scan the network**: Quickly discovers active devices on the local network.
2. **Scan the network with open ports**: Identifies open ports and associated services on devices.
3. **Scan a custom range of IPs and ports**: Allows you to specify IP and port ranges to scan.
4. **Save results to CSV or JSON file**: Export scan results to CSV or JSON formats.
5. **Quick scan (common ports only)**: Scans only common ports (22, 80, 443).
6. **Scan with Nmap scripts**: Run Nmap’s default scripts to gather detailed information.
7. **Configure scan priority and timing**: Adjust scan speed and timing for efficiency.
8. **Filter results by port status**: Filter results based on open, closed, or filtered ports.
9. **Verify open ports with specific service**: Check the status of specific ports and the services running on them.
10. **Scheduled or automatic scanning**: Automate periodic scanning to continuously monitor your network.
11. **Exit**: Exit the program.

### Disclaimer

This tool is designed solely for educational and testing purposes. The author does not take responsibility for any misuse, damage, or unintended consequences that arise from using this tool. **Always obtain explicit permission before performing network scans** on networks you do not own or manage.

### License

AutoNMAP is released under the [MIT License](LICENSE).

---

**Developed by Nefrarius and ChatGPT**

---
**Important Notes:**

- The tool runs the default scan on the IP range `192.168.1.0/24` unless you specify a custom range.
- Ensure that the target network and devices have granted permission for scanning before using AutoNMAP.
```

