import psutil
import socket

def get_active_interfaces():
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        ip = mac = None
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
            elif addr.family == psutil.AF_LINK:
                mac = addr.address
        if ip and mac:
            interfaces.append({
                "name": name,
                "ip": ip,
                "mac": mac,
                "label": f"{name} ({ip}) [{mac}]"
            })
    return interfaces
