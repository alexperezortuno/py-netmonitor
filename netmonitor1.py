import os
import socket
import psutil
import platform


def get_active_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_ESTABLISHED and conn.laddr and conn.raddr:
            pid = conn.pid
            if pid:
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                    remote_ip = conn.raddr.ip
                    connections.append((process_name, remote_ip))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    return connections


def main():
    system = platform.system()
    print(f"Detecting active connections on {system}...\n")

    active_connections = get_active_connections()
    if not active_connections:
        print("No active connections found.")
        return

    print("{:<30} {:<20}".format("Application", "Remote IP"))
    print("-" * 50)

    for app, ip in active_connections:
        print(f"{app:<30} {ip:<20}")


if __name__ == "__main__":
    main()
