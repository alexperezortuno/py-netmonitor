import os
import psutil
import platform
import datetime

# Archivo donde se almacenarán las conexiones sospechosas
LOG_FILE = "connections.log"
MALICIOUS_IPS_FILE = "malicious_ips.txt"


# Lista de IPs maliciosas (puedes actualizar el archivo con IPs de listas negras)
def load_malicious_ips():
    if os.path.exists(MALICIOUS_IPS_FILE):
        with open(MALICIOUS_IPS_FILE, "r") as f:
            return set(line.strip() for line in f)
    return set()


# Obtiene las conexiones activas con IPs y puertos
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
                    is_malicious = remote_ip in malicious_ips
                    connections.append((process_name, remote_ip, remote_port, is_malicious))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    return connections


# Guarda las conexiones en un archivo de log
def log_connections(connections):
    with open(LOG_FILE, "a") as log:
        log.write(f"\n--- Connection log {datetime.datetime.now()} ---\n")
        for app, ip, port, is_malicious in connections:
            log.write(f"{app} -> {ip}:{port} {'(MALICIOUS)' if is_malicious else ''}\n")


# Muestra y guarda las conexiones
def main():
    system = platform.system()
    print(f"Detecting active connections on {system}...\n")

    active_connections = get_active_connections()
    if not active_connections:
        print("No active connections found.")
        return

    print("{:<30} {:<20} {:<10} {}".format("Application", "Remote IP", "Port", "Status"))
    print("-" * 70)

    for app, ip, port, is_malicious in active_connections:
        status = "MALICIOUS" if is_malicious else "Safe"
        print(f"{app:<30} {ip:<20} {port:<10} {status}")

    # Guardar en log
    log_connections(active_connections)
    print(f"\nConnections have been logged in {LOG_FILE}")


if __name__ == "__main__":
    main()
