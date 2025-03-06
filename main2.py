import os
import socket
import psutil
import platform
import datetime
import json
import csv
import requests
import pandas as pd
import tkinter as tk
from tkinter import ttk, messagebox

# Archivos de log y lista negra
LOG_FILE = "connections.log"
MALICIOUS_IPS_FILE = "malicious_ips.txt"
EXPORT_JSON = "connections.json"
EXPORT_CSV = "connections.csv"
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN")  # Puedes obtener un token gratuito en https://ipinfo.io/signup


# Cargar lista de IPs maliciosas
def load_malicious_ips():
    if os.path.exists(MALICIOUS_IPS_FILE):
        with open(MALICIOUS_IPS_FILE, "r") as f:
            return set(line.strip() for line in f)
    return set()


# Obtener geolocalización de una IP usando ipinfo.io
def get_ip_location(ip):
    if not IPINFO_TOKEN:
        return "Unknown"
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}")
        data = response.json()
        return data.get("country", "Unknown")
    except:
        return "Unknown"


# Obtener conexiones activas
def get_active_connections():
    connections = []
    malicious_ips = load_malicious_ips()

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_ESTABLISHED and conn.laddr and conn.raddr:
            pid = conn.pid
            if pid:
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    country = get_ip_location(remote_ip)
                    is_malicious = remote_ip in malicious_ips
                    connections.append((process_name, remote_ip, remote_port, country, is_malicious))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    return connections


# Guardar en archivo de log
def log_connections(connections):
    with open(LOG_FILE, "a") as log:
        log.write(f"\n--- Log {datetime.datetime.now()} ---\n")
        for app, ip, port, country, is_malicious in connections:
            log.write(f"{app} -> {ip}:{port} ({country}) {'(MALICIOUS)' if is_malicious else ''}\n")


# Exportar a JSON
def export_to_json(connections):
    data = [{"Application": app, "IP": ip, "Port": port, "Country": country, "Malicious": is_malicious}
            for app, ip, port, country, is_malicious in connections]
    with open(EXPORT_JSON, "w") as json_file:
        json.dump(data, json_file, indent=4)


# Exportar a CSV
def export_to_csv(connections):
    df = pd.DataFrame(connections, columns=["Application", "IP", "Port", "Country", "Malicious"])
    df.to_csv(EXPORT_CSV, index=False)


# Mostrar conexiones en terminal
def show_connections():
    connections = get_active_connections()
    if not connections:
        print("No active connections found.")
        return

    print("{:<30} {:<20} {:<10} {:<10} {}".format("Application", "Remote IP", "Port", "Country", "Status"))
    print("-" * 80)

    for app, ip, port, country, is_malicious in connections:
        status = "MALICIOUS" if is_malicious else "Safe"
        print(f"{app:<30} {ip:<20} {port:<10} {country:<10} {status}")

    log_connections(connections)
    export_to_json(connections)
    export_to_csv(connections)
    print(f"\nData save in {LOG_FILE}, {EXPORT_JSON} y {EXPORT_CSV}")


# Interfaz gráfica con Tkinter
class ConnectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitor Connections")
        self.root.geometry("700x400")

        self.tree = ttk.Treeview(root, columns=("Application", "IP", "Port", "Country", "Status"), show="headings")
        self.tree.heading("Application", text="Application")
        self.tree.heading("IP", text="Remote IP")
        self.tree.heading("Port", text="Port")
        self.tree.heading("Country", text="Country")
        self.tree.heading("Status", text="Status")
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.refresh_button = ttk.Button(root, text="Update", command=self.refresh_connections)
        self.refresh_button.pack(pady=10)

        self.refresh_connections()

    def refresh_connections(self):
        self.tree.delete(*self.tree.get_children())
        connections = get_active_connections()

        if not connections:
            messagebox.showinfo("Info", "No active connections found.")
            return

        for app, ip, port, country, is_malicious in connections:
            status = "MALICIOUS" if is_malicious else "Safe"
            self.tree.insert("", "end", values=(app, ip, port, country, status))

        log_connections(connections)
        export_to_json(connections)
        export_to_csv(connections)


# Modo CLI o GUI
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        show_connections()
    else:
        root = tk.Tk()
        app = ConnectionApp(root)
        root.mainloop()
