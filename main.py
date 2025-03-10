import os
import psutil
import datetime
import json
import requests
import pandas as pd
import tkinter as tk
from tkinter import ttk, messagebox
import plotly.express as px
import streamlit as st
import logging
import coloredlogs

# Archivos de configuración
LOG_FILE = "connections.log"
MALICIOUS_IPS_FILE = "malicious_ips.txt"
EXPORT_JSON = "connections.json"
EXPORT_CSV = "connections.csv"
log_str: str = os.getenv("LOG_FORMAT", f"%(asctime)s | %(name)s | %(lineno)d | %(levelname)s | %(message)s")
log_lvl: str = os.getenv("LOG_LEVEL", "debug")

def get_logger(log_level: str, log_format: str, name: str = None) -> logging.Logger:
    res = logging.getLogger(__name__) if name is None else logging.getLogger(name)
    coloredlogs.install(level=log_level.upper(), fmt=log_format)
    return res

logger = get_logger(log_lvl, log_str)

# Load environment variables from .env file if exists
def load_env() -> None:
    from dotenv import load_dotenv
    load_dotenv()
    logger.debug("Environment variables loaded")

# Create files if not exist
def create_files() -> None:
    for file in [LOG_FILE, MALICIOUS_IPS_FILE, EXPORT_JSON, EXPORT_CSV]:
        if not os.path.exists(file):
            logger.info(f"Creating file {file}")
            with open(file, "w"):
                pass

# Cargar lista de IPs maliciosas
def load_malicious_ips() -> set:
    if os.path.exists(MALICIOUS_IPS_FILE):
        with open(MALICIOUS_IPS_FILE, "r") as f:
            return set(line.strip() for line in f)
    return set()

# Obtener geolocalización de una IP usando ipinfo.io
def get_ip_location(ip) -> str:
    IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN")   # Obtén un token gratuito en https://ipinfo.io/signup
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}")
        data = response.json()
        return data.get("country", "Unknown")
    except requests.RequestException:
        logger.error(f"Failed to get IP location from {ip}")
        return "Unknown"

# Obtener conexiones activas
def get_active_connections() -> list:
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
def log_connections(connections) -> None:
    with open(LOG_FILE, "a") as log:
        log.write(f"\n--- Log {datetime.datetime.now()} ---\n")
        for app, ip, port, country, is_malicious in connections:
            log.write(f"{app} -> {ip}:{port} ({country}) {'(MALICIOUS)' if is_malicious else ''}\n")

# Exportar a JSON
def export_to_json(connections) -> None:
    data = [{"Application": app, "IP": ip, "Port": port, "Country": country, "Malicious": is_malicious}
            for app, ip, port, country, is_malicious in connections]
    with open(EXPORT_JSON, "w") as json_file:
        json.dump(data, json_file, indent=4)

# Exportar a CSV
def export_to_csv(connections) -> None:
    df = pd.DataFrame(connections, columns=["Application", "IP", "Port", "Country", "Malicious"])
    df.to_csv(EXPORT_CSV, index=False)

# Mostrar conexiones en terminal
def show_connections() -> None:
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
    print(f"\nConnections saved in {LOG_FILE}, {EXPORT_JSON}, and {EXPORT_CSV}")

# Interfaz gráfica con Tkinter
class ConnectionApp:
    def __init__(self, root) -> None:
        self.root = root
        self.root.title("Connections Monitor")
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

    def refresh_connections(self) -> None:
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

# Interfaz web con Streamlit
def web_interface() -> None:
    st.title("Real-Time Connection Monitor")
    st.write("This system monitors active connections on your system and detects potential threats.")

    connections = get_active_connections()
    df = pd.DataFrame(connections, columns=["Application", "IP", "Port", "Country", "Malicious"])

    # Mostrar tabla
    st.dataframe(df)

    # Gráfica de conexiones por país
    fig = px.histogram(df, x="Country", title="Connections by Country")
    st.plotly_chart(fig)

    # Exportar datos
    st.download_button("Download CSV", df.to_csv(index=False), file_name=EXPORT_CSV, mime="text/csv")
    st.download_button("Download JSON", json.dumps(df.to_dict(orient="records")), file_name=EXPORT_JSON,
                       mime="application/json")

# Modo CLI, GUI o Web
if __name__ == "__main__":
    import sys

    load_env()
    create_files()
    if len(sys.argv) > 1:
        if sys.argv[1] == "--cli":
            show_connections()
        elif sys.argv[1] == "--web":
            web_interface()
        else:
            print("Use: python main.py [--cli | --web]")
    else:
        root = tk.Tk()
        app = ConnectionApp(root)
        root.mainloop()
