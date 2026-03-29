"""
Author: Cem [Soyadınızı Buraya Yazın]
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary mapping common port numbers to their standard service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and setters allows us to add validation logic (like preventing empty strings) 
    # whenever the target attribute is modified. It encapsulates the private __target variable 
    # while keeping the interface clean and Pythonic for the user.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if not value:
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner reuses the parent's __init__ constructor via super().__init__(target) to handle 
# the target IP initialization automatically. It also inherits the target property getter and 
# setter, meaning we do not have to rewrite the empty-string validation logic for the child class.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        try:
            super().__del__()
        except AttributeError:
            pass

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # If the try-except blocks were removed, attempting to connect to an unreachable machine 
        # or encountering a network disruption would throw an unhandled socket.error. This would 
        # crash the entire program immediately, and no further ports would be scanned or saved.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [res for res in self.scan_results if res[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows us to scan multiple ports concurrently, which dramatically speeds up the 
    # execution time. If we scanned 1024 ports sequentially without threads, the program would 
    # have to wait up to 1 second for every closed port, potentially taking over 17 minutes.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
            
        for t in threads:
            t.start()
            
        for t in threads:
            t.join()

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        
        scan_date = str(datetime.datetime.now())
        for result in results:
            cursor.execute("INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                           (target, result[0], result[1], result[2], scan_date))
            
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")

if __name__ == "__main__":
    try:
        target_ip = input("Target IP: ")
        if not target_ip:
            target_ip = "127.0.0.1"
            
        start_port = int(input("Start port: "))
        end_port = int(input("End port: "))
        
        if not (1 <= start_port <= 1024) or not (1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            scanner = PortScanner(target_ip)
            print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
            scanner.scan_range(start_port, end_port)
            
            open_ports = scanner.get_open_ports()
            print(f"--- Scan Results for {target_ip} ---")
            for port in open_ports:
                print(f"Port {port[0]}: {port[1]} ({port[2]})")
            print("------")
            print(f"Total open ports found: {len(open_ports)}")
            
            save_results(target_ip, open_ports)
            
            show_history = input("Would you like to see past scan history? (yes/no): ")
            if show_history.lower() == "yes":
                load_past_scans()
    except ValueError:
        print("Invalid input. Please enter a valid integer.")

# Q5: New Feature Proposal
# I would add a "Port Risk Classifier" feature that categorizes open ports by security risk level (High, Medium, Low). 
# It would use a nested if-statement during the scan loop to assign "High" to sensitive ports like 22 or 3389, 
# "Medium" to 3306, and "Low" to others.
# Diagram: See diagram_101496484.png in the repository root